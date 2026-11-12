"""Credential labels and read-only attributes shared by wallet views."""
from collections.abc import Mapping
import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget
from keri.help import helping
from keri.core import Saider

from locksmith.core import credentialing, ipexing
from locksmith.ui import colors


def credential_name(schema):
    schema = schema or {}
    return schema.get('title', 'Credential')


def attribute_label(name, schema):
    """Use the same readable field names in forms and credential reviews."""
    description = schema.get('description', 'Date' if name == 'dt' else name)
    # Timestamp annotations describe wire encoding, not part of the field label.
    return description.split(' RFC-3339')[0].split(' RFC3339')[0]


def identifier_name(vault, pre):
    if not pre:
        return 'Not specified'
    hab = vault.hby.habByPre(pre)
    contact = vault.org.get(pre) or {}
    name = hab.name if hab else contact.get('alias')
    if not name:
        return pre[:10] + '…' + pre[-6:]
    peers = {h.pre for h in vault.hby.habs.values() if h.name == name}
    peers.update(c['id'] for c in vault.org.list() if c.get('alias') == name)
    return f'{name} ({pre[:8]}…)' if len(peers) > 1 else name


# Core chain-refusal reasons name AIDs and SAIDs; these patterns turn each into one sentence.
_AID = r'(?P<{}>[A-Za-z0-9_-]{{20,}})'
_REFUSALS = (
    (re.compile(r'I1I edge to node (?P<node>\S+) requires equal issuers; near issuer '
                + _AID.format('near') + r' != far issuer ' + _AID.format('far')),
     "This credential's linked {title} was issued by a different issuer ({far}), but the link "
     "requires the same issuer (I1I)."),
    (re.compile(r'DI1I edge to node (?P<node>\S+) fails because near issuer ' + _AID.format('near')
                + r' is not delegated from far issuer ' + _AID.format('far')),
     "This credential's issuer ({near}) is neither the issuer of its linked {title} ({far}) nor an "
     "anchored delegate of it, but the link requires one of them (DI1I)."),
    (re.compile(r'(?P<op>DI1I|DI2I) edge to node (?P<node>\S+) is missing KEL or delegation-anchor evidence '
                r'between near issuer ' + _AID.format('near') + r' and far (?P<role>issuer|issuee) '
                + _AID.format('far')),
     "The wallet cannot yet confirm that {near} is a delegate of {far}, the {role} of the linked "
     "{title}, because that delegation's KEL or anchor has not arrived ({op}). Try again after it arrives."),
    (re.compile(r'DI2I edge to node (?P<node>\S+) fails because near issuer ' + _AID.format('near')
                + r' is not delegated from far issuee ' + _AID.format('far')),
     "This credential's issuer ({near}) is neither the issuee of its linked {title} ({far}) nor an "
     "anchored delegate of it, but the link requires one of them (DI2I)."),
    (re.compile(r'I2I edge to node (?P<node>\S+) requires the near issuer to be the far issuee; issuer '
                + _AID.format('near') + r' != far issuee ' + _AID.format('far')),
     "This credential's linked {title} was issued to {far}, but the link requires it to be issued to "
     "this credential's issuer, {near} (I2I)."),
    (re.compile(r'I2I edge to node (?P<node>\S+) requires a targeted far node, which has no issuee'),
     "This credential's linked {title} has no issuee, but the link requires its issuee to be this "
     "credential's issuer (I2I)."),
    (re.compile(r'E1E edge to node (?P<node>\S+) requires equal issuees; near issuee (?P<near>\S+) != far '
                r'issuee (?P<far>\S+)'),
     "This credential's linked {title} has a different issuee ({far}), but the link requires the same "
     "issuee (E1E)."),
    (re.compile(r'unrecognized unary Operator\(s\) (?P<ops>\[[^\]]*\]) on edge to node (?P<node>\S+?);'),
     "The link to {title} uses operator {ops}, which verifiers cannot evaluate."),
    (re.compile(r'edge is missing far node (?P<node>\S+)'),
     "The linked credential {node} is not part of this selection."),
)


def refusal_text(vault, reason):
    """Explain core chain-refusal ``reason`` in sentences, keeping text it does not recognize.

    Each recognized relation refusal becomes one sentence naming the linked
    credential's title and the identifiers involved; the original reason stays
    available to callers for diagnostics.
    """
    sentences = []
    for pattern, template in _REFUSALS:
        for match in pattern.finditer(reason or ''):
            values = match.groupdict()
            node = values.get('node', '').rstrip(';,')
            try:
                title = credential_name(credentialing.credential(vault, node)['schema'])
            except Exception:
                title = 'credential'
            values.update(title=title, node=node[:12] + '…')
            for key in ('near', 'far'):
                if values.get(key) and values[key] != 'None':
                    values[key] = identifier_name(vault, values[key])
            sentence = template.format(**values)
            if sentence not in sentences:
                sentences.append(sentence)
    return ' '.join(sentences) if sentences else reason


def date_label(stamp):
    if not stamp:
        return '—'
    try:
        return helping.fromIso8601(stamp).astimezone().strftime('%b %d, %Y %H:%M')
    except (ValueError, TypeError):
        return stamp


def status_label(status):
    return {'issued': 'Active', 'revoked': 'Revoked', 'pending': 'Pending verification',
            'authenticated': 'Authenticated'}.get(status.get('et'), 'Unknown state')


def rules_text(rules):
    """Keep disclosed terms readable without treating a commitment as rule text."""
    if not isinstance(rules, Mapping):
        try:
            if Saider(qb64=rules).qb64 == rules:
                return 'Rule text has not been disclosed.'
        except Exception:
            pass
        return rules
    values = {('Legal terms' if key == 'l' else key): value if key == 'l' else rules_text(value)
              for key, value in rules.items() if key not in ('d', 'u')}
    if list(values) == ['Legal terms']:
        return values['Legal terms']
    return values or 'Rule text has not been disclosed.'


def disclosed_credentials(vault, said, *, metadata=False, **selection):
    """Read exact composer nodes for display, without expanding a selected grant.

    vault/said select inventory; metadata hides credential attributes in the
    established metadata Offer form. selection carries explicit from_grant,
    disclose, preview and optional Grant state-opening controls to the composer.
    Return disclosed SADs or propagate the same missing-capability error as send.
    """
    selection.setdefault('preview', metadata)
    _, _, _, nodes = ipexing._credential_evidence(vault, said, **selection)
    if metadata:
        return [ipexing._offer_preview(nodes[said]).sad]
    return list(nodes.values())


def credential_details(vault, sad, *, identity=True):
    """Show a retained credential's identity, disclosed attributes, and terms."""
    schema = sad.get('s', {})
    if isinstance(schema, str):
        schemer = vault.hby.db.schema.get((schema,))
        schema = schemer.sed if schemer else {}
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 12)
    if identity:
        layout.addWidget(attribute_view(credential_name(schema), 'Issued by ' + identifier_name(vault, sad.get('i'))))
    attrs = sad.get('a')
    if isinstance(attrs, Mapping):
        if identity:
            layout.addWidget(attribute_view('Credential subject', identifier_name(vault, attrs.get('i'))))
        definition = schema.get('properties', {}).get('a', {})
        definition = definition if isinstance(definition, Mapping) else {}
        definition = next((item for item in definition.get('oneOf', [definition])
                           if isinstance(item, Mapping) and item.get('type') == 'object'), {})
        for name, value in attrs.items():
            if name in ('d', 'i', 'u'):
                continue
            prop = definition.get('properties', {}).get(name, {})
            prop = prop if isinstance(prop, Mapping) else {}
            layout.addWidget(attribute_view(attribute_label(name, prop), value, prop))
    elif attrs is not None:
        layout.addWidget(attribute_view('Attributes', 'Withheld until the Grant.' if attrs == '' else 'Only a commitment is disclosed.'))
    if 'A' in sad:
        layout.addWidget(attribute_view('Disclosed aggregate', sad['A']))
    layout.addWidget(attribute_view('Terms', rules_text(sad['r']) if sad.get('r') else 'No rules attached.'))
    return widget


def attribute_view(label, value, schema=None):
    """Display disclosed values without editable controls or JSON syntax."""
    schema = schema if isinstance(schema, Mapping) else {}
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 8)
    title = QLabel(label)
    title.setTextFormat(Qt.TextFormat.PlainText)
    title.setStyleSheet(f'font-weight: bold; color: {colors.TEXT_SECONDARY};')
    title.setWordWrap(True)
    layout.addWidget(title)
    if isinstance(value, Mapping):
        properties = schema.get('properties', {})
        for name, item in value.items():
            prop = properties.get(name, {})
            prop = prop if isinstance(prop, Mapping) else {}
            child = attribute_view(attribute_label(name, prop), item, prop)
            child.layout().setContentsMargins(16, 0, 0, 8)
            layout.addWidget(child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            layout.addWidget(attribute_view(str(index + 1), item, schema.get('items', {})))
    else:
        text = ('Yes' if value else 'No') if isinstance(value, bool) else str(value if value is not None else '')
        content = QLabel(text or '—')
        content.setTextFormat(Qt.TextFormat.PlainText)
        content.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse |
                                        Qt.TextInteractionFlag.TextSelectableByKeyboard)
        content.setWordWrap(True)
        layout.addWidget(content)
    return widget
