# Chairs-form dependency register (S-01)

First registered: W7, 2026-11-26.

This file registers, item by item, every form dependency on the WIMSE
working group chairs' side that the S-01 suite relies on, with its true
status. Rules:

- One row per item, by name. A status changes only on evidence (a reply
  received, with its date and where it is recorded); the evidence goes in
  the row.
- An item still awaiting a reply stays **AWAITING REPLY**. An unanswered
  item is never recorded as answered, approved or "no objection".
- Awaiting a reply does not block a wave; the wave that depends on the
  item says so in its own record.
- Rows are not deleted. A closed item keeps its row with its closing
  evidence.

Status values: `AWAITING REPLY` (sent, no reply yet), `NOT SENT` (not yet
submitted), `ANSWERED` (a reply is on record; cite it), `CLOSED` (no
further action; cite why).

## Register

| Item | What it depends on | Sent | Status | Evidence | Blocks |
| --- | --- | --- | --- | --- | --- |
| C-1: Chairs letter reply specifying the contribution form （贡献形态） | The draft's chairs specifying the expected contribution form, asked for in the contribution letter | Yes, via the contribution letter | **AWAITING REPLY** （回复未到） | Item from the suite design doc, §5.1 acceptance row 4 and its uncovered-surface note 1; supplied 2026-11-26. No reply is on record | Nothing: this is an open dependency by design and does not block W7. Until the reply arrives, the repository form and the citation/maintenance wording follow the brief's interim wording. When it arrives, the README and this register are revised together, and the change is logged in [VERSION-MAP.md](../VERSION-MAP.md) |

## Intake gap at W7 (closed 2026-11-26)

When this register was first created at W7, the item list (which lives in
the S-01 suite design, not in this repository) had not been supplied, so
no item was registered. The design's list was then supplied: §5.1
acceptance row 4 and its uncovered-surface note 1 name exactly one
chairs-side item, registered above as C-1. C-1 is **not** answered; its
status is AWAITING REPLY.
