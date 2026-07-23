# GL320MG Config Tool

Web-based configuration and OTA deployment management for Queclink GL320MG
trackers.

## Operator workflow

1. Open **Config Workspace** and choose a tracker, server file, template, or
   local file.
2. Edit the configuration sections. The workspace shows when the draft has
   unsaved changes.
3. Return to **Config Workspace** to review validation and the generated
   configuration.
4. Save a reusable draft or review and queue a complete `<IMEI>.ini` update.

Imported commands that the editor does not understand are preserved verbatim.
Non-command lines are reported and excluded from tracker output.

## Deployment lifecycle

Queueing a file and the tracker downloading it are separate states:

- `queued`: the `<IMEI>.ini` file is waiting for the tracker.
- `downloaded`: the server returned the complete file with HTTP 200, but
  application by the tracker has not been independently verified.

HTTP 206 responses do not delete the file. Each update queues a complete
configuration, so another update cannot accidentally be calculated against a
configuration the tracker never received.

## Tests

```sh
cd api
npm install
npm test
```

The test suite covers parsing and preservation, stable command diffs, config
listing, and the queued deployment API lifecycle.
