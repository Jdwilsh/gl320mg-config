# GL320MG Config Tool

Web-based configuration and OTA deployment management for Queclink GL320MG
trackers.

## Operator workflow

1. Open **Configurations** and choose or create a reusable configuration.
2. Load a trusted complete baseline, then edit and validate its settings.
3. Assign a tracker. Assignment immediately queues that configuration as the
   tracker's complete `<IMEI>.ini` file.
4. After later edits, use **Queue update for all** to replace the waiting file
   for every tracker assigned to that configuration.

Imported commands that the editor does not understand are preserved verbatim.
Non-command lines are reported and excluded from tracker output.

## Deployment lifecycle

Queueing a file and the tracker downloading it are separate states:

- `queued`: the `<IMEI>.ini` file is waiting for the tracker.
- `downloaded`: the server returned the complete file with HTTP 200 or a
  complete ranged HTTP 206 response, but
  application by the tracker has not been independently verified.

After a confirmed complete download, the waiting file is removed so it cannot
be downloaded repeatedly. Each update queues a complete configuration, so
another update cannot accidentally be calculated against a configuration the
tracker never received.

## Tests

```sh
cd api
npm install
npm test
```

The test suite covers parsing and preservation, stable command diffs, config
listing, and the queued deployment API lifecycle.
