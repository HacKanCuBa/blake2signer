Added
-----

- Add support for signing secret rotation: now it supports receiving a sequence of secrets instead of a single one, considering them ordered from oldest to newest, so that signatures are made with the newest secret but verifications are done using all of them.
