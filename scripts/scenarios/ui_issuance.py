"""Live issuance through the real form, with private test-provider OTP input.

Local qualification adapter. Recipient naming is bootstrap metadata over an
already verified KEL. No accepted protocol rows or signed bytes are injected.
"""
import json
from pathlib import Path
from time import monotonic, time
from urllib.parse import parse_qs, urlsplit

import pyotp
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
from locksmith.core import credentialing, evidence
from locksmith.ui.vault.credentials.issued.issue import IssueCredentialDialog


def issue(app, page, request, folder, select, click, capture):
    """Operate one visible entitlement form and await its actual receipt result.

    app/page own the vault and Issued Credentials page. request supplies public
    schema/recipient/attribute/mode choices. folder receives public screenshots;
    auth inputs are read from the scenario's private hosted-provider bootstrap.
    The passed helpers perform keyboard interaction and public screenshot capture.
    """
    click(page.table.header.add_button)
    yield
    dialog = next(widget for widget in QApplication.topLevelWidgets()
                  if isinstance(widget, IssueCredentialDialog) and widget.isVisible())
    deadline = monotonic() + request.get('timeout', 60)
    try:
        select(dialog.schema_dropdown.combo_box, request['schema'])
        select(dialog.recipient_dropdown.combo_box, request['recipient'])
        select(dialog.state_options.mode.combo_box, request.get('registry_mode', 'public'))
        for name, value in request['attributes'].items():
            field = dialog._dynamic_field_widgets[name]['widget'].line_edit
            dialog.scroll_area.ensureWidgetVisible(field)
            field.setFocus()
            QTest.keyClicks(field, value)
        settled = monotonic() + .25
        while monotonic() < settled:
            yield
        capture(dialog, folder, 'issuance-form')
        click(dialog.issue_button, dialog)
        yield
        if dialog._workflow_mode != 'auth':
            raise ValueError(dialog.error_label.text() or 'Expected hosted-witness authentication')
        # The UI accepts manual current codes. Avoid typing across a TOTP boundary;
        # exact timestamped headers remain a separate headless-driver capability.
        while time() % 30 > 20:
            yield
        root = folder.parents[1]
        for witness, field in dialog._auth_panel.passcode_fields.items():
            if not isinstance(witness, str):
                raise ValueError('This profile expects three independent hosted witnesses')
            path = root / 'private' / f'issuer-{witness}.txt'
            url = next(line for line in path.read_text().splitlines() if line.startswith('otpauth://'))
            seed = parse_qs(urlsplit(url).query)['secret'][0]
            dialog.scroll_area.ensureWidgetVisible(field)
            field.line_edit.setFocus()
            QTest.keyClicks(field.line_edit, pyotp.TOTP(seed).now())
        # Never capture the authentication panel or its private one-time codes.
        click(dialog.issue_button, dialog)
        while dialog._workflow_mode != 'issued':
            if dialog.error_label.text():
                raise ValueError(dialog.error_label.text())
            if monotonic() >= deadline:
                raise TimeoutError('UI issuance is still pending; inspect retained authoring state')
            yield
        said = dialog._issued_said
        record = app.vault.db.issued.get((said,))
        view = credentialing.credential(app.vault, said)
        registry = view['sad']['rd']
        with (folder / 'actions.jsonl').open('a') as log:
            log.write(json.dumps({'control': type(dialog).__name__, 'action': 'issue',
                                  'credential': said, 'registry': registry}) + '\n')
        return {'credential': said, 'registry': registry, 'update': record.update,
                'sad': view['sad'], 'stream': record.stream, 'accepted': True,
                'registry_evidence': evidence.processor(app.vault).clone([registry]).decode()}
    finally:
        dialog.close()
