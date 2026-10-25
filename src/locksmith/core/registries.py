"""Publish registry evidence and verify observer replies against the wallet KEL."""
from time import monotonic

from hio.base import doing
from PySide6.QtCore import QUrl
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest
from keri import kering

from locksmith.core import evidence


class RegistrySyncDoer(doing.DoDoer):
    """Publish to a registrar or retrieve from an observer without blocking Qt.

    Exactly one endpoint is required. ``result`` holds the verified state or
    accepted publication summary. ``error`` remains empty on success.
    """

    Timeout = 20.0
    MaxResponse = 8 * 1024 * 1024

    def __init__(self, vault, hab, regk, *, observer_url=None, registrar_url=None, **kwa):
        """Configure one registry operation for ``hab`` in the open ``vault``.

        ``regk`` identifies the registry. Exactly one of ``observer_url`` or
        ``registrar_url`` selects retrieval or publication; ``kwa`` goes to
        HIO. Construction starts no network request."""
        if bool(observer_url) == bool(registrar_url):
            raise ValueError('Provide either an observer URL or a registrar URL')
        self.vault, self.hab, self.regk = vault, hab, regk
        self.observer_url, self.registrar_url = observer_url, registrar_url
        self.result, self.error, self.manager = None, '', None
        self.response_headers = {}
        self.fresh_until = None
        super().__init__(doers=[doing.doify(self.sync_do)], **kwa)

    def recur(self, tyme, deeds=None):
        """Advance HIO children at ``tyme`` and convert child errors to signals.

        ``deeds`` is the optional scheduler queue. Return completion on child
        failure so normal HIO exit can close network resources."""
        try:
            return super().recur(tyme, deeds)
        except Exception as ex:
            # HIO child exceptions otherwise escape the vault's scheduler. The
            # parent doer's normal exit closes the client and Qt reply.
            self.error = f'Registry evidence operation failed: {ex}'
            if signals := getattr(self.vault, 'signals', None):
                signals.emit_doer_event('RegistrySync', 'registry_failed', {
                    'registry': self.regk, 'success': False, 'error': self.error})
            return True

    def _open(self):
        """Refuse work after vault closure or with another vault's identifier."""
        if (getattr(self.vault, 'closed', False) or not self.vault.hby.db.opened
                or not self.vault.rgy.store.opened):
            raise ValueError('The vault is closed')
        if self.vault.hby.habByPre(self.hab.pre) is not self.hab:
            raise ValueError('The query identifier does not belong to this vault')

    def _request(self, url, body, content_type):
        """Yield through one bounded Qt request and return its response bytes.

        ``url``, signed ``body`` and ``content_type`` define the POST request.
        No redirects are followed. Retain response headers for freshness
        checks, reject timeout/oversize/non-OK
        replies and always abort/delete the reply on failure or cancellation."""
        self._open()
        target = QUrl(url)
        if target.scheme() not in ('http', 'https') or not target.host():
            raise ValueError('Registry services require an HTTP or HTTPS URL')
        request = QNetworkRequest(target)
        request.setHeader(QNetworkRequest.KnownHeaders.ContentTypeHeader, content_type)
        # A signed request must not be redirected to another endpoint.
        request.setAttribute(QNetworkRequest.Attribute.RedirectPolicyAttribute,
                             QNetworkRequest.RedirectPolicy.ManualRedirectPolicy)
        reply = self.manager.post(request, body)
        reply.setReadBufferSize(self.MaxResponse + 1)
        deadline = monotonic() + self.Timeout
        try:
            while not reply.isFinished():
                self._open()
                if reply.bytesAvailable() > self.MaxResponse:
                    raise ValueError('Registry response exceeds the size limit')
                if monotonic() >= deadline:
                    raise TimeoutError('Registry service request timed out')
                yield self.tock
            self._open()
            status = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
            if status != 200 or reply.error() != QNetworkReply.NetworkError.NoError:
                raise kering.ValidationError(f'Registry service refused the request (HTTP {status})')
            if reply.bytesAvailable() > self.MaxResponse:
                raise ValueError('Registry response exceeds the size limit')
            self.response_headers = {bytes(key).decode().lower(): bytes(value).decode()
                                     for key, value in reply.rawHeaderPairs()}
            return bytes(reply.readAll())
        finally:
            if not reply.isFinished():
                reply.abort()
            reply.deleteLater()

    def sync_do(self, tymth, tock=0.0, **opts):
        """Run the selected publication or authenticated retrieval cooperatively.

        ``tymth``/``tock`` and ``opts`` are HIO scheduling inputs. Store the
        verified result on this worker, report errors through vault signals,
        and release the Qt manager on every exit path."""
        self.wind(tymth)
        yield self.tock
        try:
            self._open()
            self.manager = QNetworkAccessManager()
            event = yield from evidence.sync(self)
            if signals := getattr(self.vault, 'signals', None):
                signals.emit_doer_event('RegistrySync', event, {'registry': self.regk, 'success': True})
        except Exception as ex:
            self.error = str(ex)
            if signals := getattr(self.vault, 'signals', None):
                signals.emit_doer_event('RegistrySync', 'registry_failed',
                                       {'registry': self.regk, 'success': False, 'error': self.error})
        finally:
            if self.manager is not None:
                self.manager.deleteLater()
                self.manager = None
        return True


def required(sad):
    """List registry declarations actually disclosed in this credential."""
    sections = [sad]
    if isinstance(sad.get('a'), dict):
        sections.append(sad['a'])
    aggregate = sad.get('A')
    if isinstance(aggregate, list):
        sections.extend(block for block in aggregate[1:] if isinstance(block, dict))
    return list(dict.fromkeys(section['rd'] for section in sections
                             if isinstance(section.get('rd'), str) and section['rd']))


class RegistryEvidenceDoer(doing.DoDoer):
    """Keep disclosed registry evidence current for one open vault.

    Work is reconstructed from issued credentials, accepted Grants, and ACDC v2 registry
    proof escrow. Successful freshness and publication checks are never carried
    across a vault reopen. Services are configured in ``hby.cf['registries']``.
    """

    Retry = 5.0
    MaxRetry = 300.0
    MaxActive = 8
    LaunchesPerTurn = 4

    def __init__(self, vault, **kwa):
        """Own refresh workers and empty session caches for ``vault``.

        Read service URLs from the vault config; ``kwa`` passes to
        HIO. Reopening never restores a prior session's freshness deadline."""
        self.vault = vault
        config = (vault.hby.cf.get() or {}).get('registries', {})
        self.registrar_url = config.get('registrar')
        self.observer_url = config.get('observer')
        self.errors = {}
        self._requests, self._fetched, self._published = {}, {}, {}
        self._active, self._retry, self._failures = {}, {}, {}
        self._launch_cursor = None
        super().__init__(doers=[doing.doify(self.sync_do)], **kwa)

    def _configure(self):
        """Cancel old workers and clear freshness when service configuration changes."""
        config = (self.vault.hby.cf.get() or {}).get('registries', {})
        endpoints = config.get('registrar'), config.get('observer')
        if endpoints != (self.registrar_url, self.observer_url):
            self.remove(list(self._active.values()))
            self._active.clear()
            self._fetched.clear()
            self._published.clear()
            self._retry.clear()
            self._failures.clear()
            self.errors.clear()
            self._launch_cursor = None
            self.registrar_url, self.observer_url = endpoints

    def ensure(self, regk, hab):
        """Queue a registry check and return whether its observer evidence is fresh."""
        self._configure()
        if self.vault.hby.habByPre(hab.pre) is not hab:
            raise ValueError('The query identifier does not belong to this vault')
        self._requests[regk] = hab
        if not self.observer_url:
            self.errors[regk] = 'Open Settings and configure an observer URL to verify current registry status'
            return False
        fetched = self._fetched.get(regk)
        head = self.vault.rgy.store.head(regk)
        return bool(fetched and head and fetched[0] == head.qb64
                    and monotonic() < fetched[1])

    def published(self, regk):
        """Return whether the registrar accepted the current local registry head."""
        self._configure()
        head = self.vault.rgy.store.head(regk)
        return bool(head and self._published.get(regk) == head.qb64)

    def _discover(self, proofs):
        """Queue registry references from accepted state and ``proofs`` grant SAIDs.

        This is discovery only: parsed references do not grant acceptance or
        freshness. Actual acquisition and verification belong to sync workers."""
        from keri.peer import exchanging

        default = next(iter(self.vault.hby.habs.values()), None)
        if default is None:
            return
        # Existing accepted registry heads are polled even after a restart.
        for (regk,), _ in self.vault.rgy.baser.heads.getTopItemIter():
            self._requests.setdefault(regk, default)
        grants = {record.grant for _, record in self.vault.db.accepted.getTopItemIter()}
        grants.update(said for (said,), _ in self.vault.hby.db.epse.getTopItemIter())
        grants.update(proofs)
        for said in grants:
            exn = (self.vault.hby.db.epse.get((said,))
                   or self.vault.hby.db.exns.get((said,)))
            if exn is None:
                continue
            hab = self.vault.hby.habByPre(exn.sad.get('ri', '')) or default
            for nest in exchanging.loadParsedNestedSubstreams(self.vault.hby, said):
                for regk in required(nest.serder.sad):
                    self._requests.setdefault(regk, hab)

    def sync_do(self, tymth, tock=0.0, **opts):
        """Schedule independent fetch/publication workers while this vault is open.

        ``tymth``/``tock`` and ``opts`` are HIO inputs. Yield between scans;
        retain the observer's original freshness deadline rather than creating
        a new window at receipt. Retry failed workers after a bounded delay,
        and cancel every active child when the generator exits."""
        self.wind(tymth)
        yield self.tock
        try:
            while not getattr(self.vault, 'closed', False) and self.vault.hby.db.opened:
                self._configure()
                now = monotonic()
                for key, worker in list(self._active.items()):
                    if not worker.done:
                        continue
                    operation, regk = key
                    del self._active[key]
                    if worker.error:
                        self.errors[regk] = worker.error
                        failures = self._failures.get(key, 0) + 1
                        self._failures[key] = failures
                        exponent = min(failures - 1, 6)
                        self._retry[key] = now + min(
                            self.Retry * (2 ** exponent), self.MaxRetry)
                    else:
                        self.errors.pop(regk, None)
                        self._retry.pop(key, None)
                        self._failures.pop(key, None)
                        if operation == 'fetch':
                            # Receiving evidence does not restart the observer's deadline.
                            self._fetched[regk] = (worker.result.said, worker.fresh_until)
                        else:
                            self._published[regk] = worker.published_head
                    if signals := getattr(self.vault, 'signals', None):
                        signals.emit_doer_event('RegistryEvidence', 'status_checked', {
                            'registry': regk, 'operation': operation,
                            'success': not bool(worker.error), 'error': worker.error})
                proofs = set()
                cues = self.vault.exc.cues
                for _ in range(len(cues)):
                    cue = cues.popleft()
                    if cue.get('kin') == 'proof':
                        if cue.get('said'):
                            proofs.add(cue['said'])
                    elif cue.get('kin') != 'saved':
                        cues.append(cue)
                # Saved messages already notify the UI through IpexHandler.handle.
                # Proof escrows persist, so retrieval can resume after configuration.
                candidates = []
                if self.observer_url:
                    self._discover(proofs)
                    for regk, hab in list(self._requests.items()):
                        key = ('fetch', regk)
                        if (not self.ensure(regk, hab) and key not in self._active
                                and now >= self._retry.get(key, 0)):
                            candidates.append((key, hab, self.observer_url))
                if self.registrar_url:
                    for (regk,), head in self.vault.rgy.baser.heads.getTopItemIter():
                        rip = self.vault.rgy.store.seqEvent(regk, 0)
                        hab = self.vault.hby.habByPre(rip.israid) if rip else None
                        if hab is None:
                            continue
                        key = ('publish', regk)
                        if (head is not None and not self.published(regk) and key not in self._active
                                and now >= self._retry.get(key, 0)):
                            candidates.append((key, hab, self.registrar_url))

                candidates.sort(key=lambda item: item[0])
                if self._launch_cursor is not None:
                    later = [item for item in candidates if item[0] > self._launch_cursor]
                    earlier = [item for item in candidates if item[0] <= self._launch_cursor]
                    candidates = later + earlier
                available = max(0, self.MaxActive - len(self._active))
                for key, hab, url in candidates[:min(available, self.LaunchesPerTurn)]:
                    operation, regk = key
                    if operation == 'fetch':
                        worker = RegistrySyncDoer(self.vault, hab, regk,
                                                  observer_url=url)
                    else:
                        worker = RegistrySyncDoer(self.vault, hab, regk,
                                                  registrar_url=url)
                        worker.published_head = self.vault.rgy.store.head(regk).qb64
                    self._active[key] = worker
                    self.extend([worker])
                    self._launch_cursor = key
                yield 1.0
        finally:
            self.remove(list(self._active.values()))
            self._active.clear()
