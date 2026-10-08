// Frida script to hook WhatsApp GIF parser for RCE analysis

var gifHooked = false;
var sandboxHooked = false;

function hookGifLib(mod) {
    if (!mod) return;
    console.log("[+] Hooking " + mod.name + " at " + mod.base + " size=" + mod.size);

    // Enumerate exports
    var exports = mod.enumerateExports();
    console.log("[*] " + mod.name + " exports: " + exports.length);
    exports.forEach(function(exp) {
        console.log("  " + exp.type + " " + exp.name + " @ " + exp.address);
    });

    // Hook JNI_OnLoad
    var jniOnLoad = mod.findExportByName("JNI_OnLoad");
    if (jniOnLoad) {
        Interceptor.attach(jniOnLoad, {
            onEnter: function(args) {
                console.log("[!] JNI_OnLoad(" + mod.name + ") vm=" + args[0]);
            },
            onLeave: function(retval) {
                console.log("[!] JNI_OnLoad(" + mod.name + ") -> " + retval);
            }
        });
    }

    // Hook the main GIF decode functions by offset
    if (mod.name === "libgifimage.so") {
        // FUN_00108f58 - largest function (2480 bytes) - likely main decoder
        var func1 = mod.base.add(0x8f58);
        Interceptor.attach(func1, {
            onEnter: function(args) {
                console.log("[!] GIF_decode_main arg0=" + args[0] + " arg1=" + args[1] + " arg2=" + args[2] + " arg3=" + args[3]);
                this.t = Date.now();
            },
            onLeave: function(retval) {
                console.log("[!] GIF_decode_main -> " + retval + " (" + (Date.now()-this.t) + "ms)");
            }
        });

        // FUN_0010cc6c - second largest (1508 bytes)
        var func2 = mod.base.add(0xcc6c);
        Interceptor.attach(func2, {
            onEnter: function(args) {
                console.log("[!] GIF_func2 arg0=" + args[0] + " arg1=" + args[1] + " arg2=" + args[2]);
            },
            onLeave: function(retval) {
                console.log("[!] GIF_func2 -> " + retval);
            }
        });

        // FUN_00108a88 - third largest (1036 bytes)
        var func3 = mod.base.add(0x8a88);
        Interceptor.attach(func3, {
            onEnter: function(args) {
                console.log("[!] GIF_func3 arg0=" + args[0] + " arg1=" + args[1]);
            },
            onLeave: function(retval) {
                console.log("[!] GIF_func3 -> " + retval);
            }
        });
    }

    if (mod.name === "libwa_sandboxed_gifimage.so") {
        // FUN_00112944 - largest (6816 bytes)
        var sf1 = mod.base.add(0x112944);
        Interceptor.attach(sf1, {
            onEnter: function(args) {
                console.log("[!] SANDBOX_decode_main arg0=" + args[0] + " arg1=" + args[1]);
                this.t = Date.now();
            },
            onLeave: function(retval) {
                console.log("[!] SANDBOX_decode_main -> " + retval + " (" + (Date.now()-this.t) + "ms)");
            }
        });
    }
}

// Monitor for library loads
Process.enumerateModules().forEach(function(m) {
    if (m.name === "libgifimage.so") { hookGifLib(m); gifHooked = true; }
    if (m.name === "libwa_sandboxed_gifimage.so") { hookGifLib(m); sandboxHooked = true; }
});

if (!gifHooked || !sandboxHooked) {
    console.log("[*] Waiting for GIF libraries to load...");
    var checks = 0;
    var iv = setInterval(function() {
        if (!gifHooked) {
            var m = Process.findModuleByName("libgifimage.so");
            if (m) { hookGifLib(m); gifHooked = true; }
        }
        if (!sandboxHooked) {
            var m2 = Process.findModuleByName("libwa_sandboxed_gifimage.so");
            if (m2) { hookGifLib(m2); sandboxHooked = true; }
        }
        checks++;
        if ((gifHooked && sandboxHooked) || checks > 120) clearInterval(iv);
    }, 500);
}

console.log("[*] Hook active. GIF libraries will load when WhatsApp processes a GIF.");
console.log("[*] To trigger: open WhatsApp, send a GIF image in a chat.");
