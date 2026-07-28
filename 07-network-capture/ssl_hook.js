'use strict';
// Capture plaintext HTTP below TLS/pinning by hooking BoringSSL SSL_read/SSL_write
// in Conscrypt (libjavacrypto.so) and the system libssl.so.
function hookMod(modname) {
  var w = Module.findExportByName(modname, "SSL_write");
  var r = Module.findExportByName(modname, "SSL_read");
  if (w) Interceptor.attach(w, {
    onEnter: function (a) {
      try {
        var n = a[2].toInt32();
        if (n > 0 && n < 262144) send({ dir: 'out', n: n }, a[1].readByteArray(n));
      } catch (e) {}
    }
  });
  if (r) Interceptor.attach(r, {
    onEnter: function (a) { this.buf = a[1]; },
    onLeave: function (ret) {
      try {
        var n = ret.toInt32();
        if (n > 0 && n < 262144) send({ dir: 'in', n: n }, this.buf.readByteArray(n));
      } catch (e) {}
    }
  });
  return (w ? 1 : 0) + (r ? 1 : 0);
}
var h = hookMod("libjavacrypto.so") + hookMod("libssl.so");
send({ dir: 'log', msg: 'ssl hooks installed: ' + h });
