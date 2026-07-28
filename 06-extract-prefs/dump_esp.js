'use strict';
// Dump androidx EncryptedSharedPreferences (ENCRYPTED_PREF.xml) contents at runtime,
// revealing any stored Hushed access token without needing the app to make a call.
Java.perform(function () {
  function dump(sp, tag) {
    try {
      var all = sp.getAll();
      var it = all.keySet().iterator();
      while (it.hasNext()) {
        var k = it.next();
        var v = all.get(k);
        send({ t: 'esp', tag: tag, k: '' + k, v: '' + v });
      }
    } catch (e) { send({ t: 'log', m: 'dump err ' + e }); }
  }
  try {
    var ESP = Java.use("androidx.security.crypto.EncryptedSharedPreferences");
    ESP.create.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var sp = ov.apply(this, arguments);
        send({ t: 'log', m: 'ESP.create intercepted' });
        dump(sp, 'create');
        return sp;
      };
    });
    // also log individual reads
    try {
      ESP.getString.overload('java.lang.String', 'java.lang.String').implementation = function (k, d) {
        var v = this.getString(k, d);
        if (v !== null) send({ t: 'esp', tag: 'getString', k: '' + k, v: '' + v });
        return v;
      };
    } catch (e) {}
    send({ t: 'log', m: 'ESP hooks installed' });
  } catch (e) {
    send({ t: 'log', m: 'no androidx EncryptedSharedPreferences: ' + e });
  }
  // Fallback: hook plain SharedPreferences.getString to catch token-looking values
  try {
    var Impl = Java.use("android.app.SharedPreferencesImpl");
    Impl.getString.implementation = function (k, d) {
      var v = this.getString(k, d);
      if (v !== null && v.length > 40 && /[A-Za-z0-9_\-]{40,}/.test(v))
        send({ t: 'esp', tag: 'plainPrefs', k: '' + k, v: '' + v });
      return v;
    };
  } catch (e) {}
});
