Java.perform(() => {

    // ── SMS ──────────────────────────────────────────────────────────────────
    try {
        const SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String",
            "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function(dest, sc, text, sentIntent, deliveryIntent) {
            send({ category: "sms", method: "sendTextMessage", args: [dest, text] });
            return this.sendTextMessage(dest, sc, text, sentIntent, deliveryIntent);
        };
    } catch(e) {}

    // ── CONTACTS ─────────────────────────────────────────────────────────────
    try {
        const ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri", "[Ljava.lang.String;",
            "android.os.Bundle", "android.os.CancellationSignal"
        ).implementation = function(uri, projection, queryArgs, cancellationSignal) {
            const uriStr = uri.toString();
            if (uriStr.includes("contacts") || uriStr.includes("phone")) {
                send({ category: "contacts", method: "ContentResolver.query", args: [uriStr] });
            }
            return this.query(uri, projection, queryArgs, cancellationSignal);
        };
    } catch(e) {}

    // ── NETWORK ──────────────────────────────────────────────────────────────
    try {
        const URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            send({ category: "network", method: "URL.openConnection", args: [this.toString()] });
            return this.openConnection();
        };
    } catch(e) {}

    try {
        const OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newCall.implementation = function(request) {
            send({ category: "network", method: "OkHttp.newCall", args: [request.url().toString()] });
            return this.newCall(request);
        };
    } catch(e) {}

    // ── CRYPTO ───────────────────────────────────────────────────────────────
    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
            send({ category: "crypto", method: "Cipher.getInstance", args: [transformation] });
            return this.getInstance(transformation);
        };
    } catch(e) {}

    // ── CLIPBOARD ────────────────────────────────────────────────────────────
    try {
        const ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.getPrimaryClip.implementation = function() {
            send({ category: "clipboard", method: "getPrimaryClip", args: [] });
            return this.getPrimaryClip();
        };
    } catch(e) {}

    // ── CAMERA ───────────────────────────────────────────────────────────────
    try {
        const CameraManager = Java.use("android.hardware.camera2.CameraManager");
        CameraManager.openCamera.overload(
            "java.lang.String",
            "android.hardware.camera2.CameraDevice$StateCallback",
            "android.os.Handler"
        ).implementation = function(cameraId, callback, handler) {
            send({ category: "camera", method: "CameraManager.openCamera", args: [cameraId] });
            return this.openCamera(cameraId, callback, handler);
        };
    } catch(e) {}

    // ── FICHIERS ─────────────────────────────────────────────────────────────
    try {
        const FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function(path) {
            if (!path.includes("cache") && !path.includes("tmp")) {
                send({ category: "file", method: "FileOutputStream", args: [path] });
            }
            return this.$init(path);
        };
    } catch(e) {}

    console.log("[*] Tracer Frida actif");
});
