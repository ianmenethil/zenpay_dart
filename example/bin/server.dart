/// Reference merchant HTTP backend for ZenPay Hosted Checkout.
library;

import 'dart:async';
import 'dart:io';

import 'package:shelf/shelf_io.dart' as shelf_io;

import 'package:zenpay_reference_backend/src/checkout_state.dart';
import 'package:zenpay_reference_backend/src/config.dart';
import 'package:zenpay_reference_backend/src/server_app.dart';

Future<void> main() async {
  final config = loadConfig();
  final store = AttemptStore();

  Timer.periodic(const Duration(minutes: 1), (_) {
    store.purgeCreatedBefore(
      DateTime.now().toUtc().subtract(
        Duration(minutes: config.checkoutStatusTtlMinutes),
      ),
    );
  });

  final handler = buildHandler(config, store);
  final server = await shelf_io.serve(
    handler,
    InternetAddress.anyIPv4,
    config.port,
    poweredByHeader: null,
  );

  logEvent('server_started', {
    'port': server.port,
    'sessionReady': sessionConfigurationErrors(config).isEmpty,
    'callbackReady': callbackConfigurationErrors(config).isEmpty,
  });

  // Without this, Ctrl-C leaves the listening socket (and the Timer.periodic
  // above) keeping the isolate alive, which is what makes the terminal that
  // launched this process hang on exit.
  await ProcessSignal.sigint.watch().first;
  await server.close(force: true);
  exit(0);
}
