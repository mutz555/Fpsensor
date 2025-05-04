SKIPUNZIP=1

# Check for Zygisk support
if [ "$(magisk --path)/.magisk/modules/.zygisk" != "$(magisk --path)/.magisk/modules/.zygisk" ]; then
  ui_print "*******************************"
  ui_print "  Zygisk tidak aktif!         "
  ui_print "  Aktifkan Zygisk di          "
  ui_print "  pengaturan Magisk terlebih   "
  ui_print "  dahulu!                      "
  ui_print "*******************************"
  abort
fi

# Extract module files
ui_print "- Mengekstrak file modul"
unzip -o "$ZIPFILE" -x 'META-INF/*' -d $MODPATH >&2

# Setup Zygisk module
mkdir -p $MODPATH/zygisk
ui_print "- Arsitektur perangkat: $ARCH"

# Prep module.prop info
VERSION=$(grep_prop version $MODPATH/module.prop)
CODENAME=$(grep_prop id $MODPATH/module.prop)

ui_print "- Menginstal Fingerprint Hardware Detection Bypasser v$VERSION"

# Copy the appropriate libraries based on device architecture
case $ARCH in
  arm64-v8a)
    ui_print "- Menyiapkan untuk arm64-v8a"
    mkdir -p $MODPATH/zygisk/arm64-v8a
    cp -f $MODPATH/libs/arm64-v8a/libfingerprint_bypasser.so $MODPATH/zygisk/arm64-v8a/
    ;;    
  arm)
    ui_print "- Menyiapkan untuk armeabi-v7a"
    mkdir -p $MODPATH/zygisk/armeabi-v7a
    cp -f $MODPATH/libs/armeabi-v7a/libfingerprint_bypasser.so $MODPATH/zygisk/armeabi-v7a/
    ;;  
  x86)
    ui_print "- Menyiapkan untuk x86"
    mkdir -p $MODPATH/zygisk/x86
    cp -f $MODPATH/libs/x86/libfingerprint_bypasser.so $MODPATH/zygisk/x86/
    ;;    
  x64)
    ui_print "- Menyiapkan untuk x86_64"
    mkdir -p $MODPATH/zygisk/x86_64
    cp -f $MODPATH/libs/x86_64/libfingerprint_bypasser.so $MODPATH/zygisk/x86_64/
    ;;    
  *)
    ui_print "*******************************"
    ui_print "  Arsitektur CPU tidak didukung "
    ui_print "*******************************"
    abort
    ;;    
esac

# Set permissions
ui_print "- Mengatur perizinan"
set_perm_recursive $MODPATH 0 0 0755 0644
set_perm_recursive $MODPATH/zygisk 0 0 0755 0644
find $MODPATH/zygisk -type f -name "*.so" -exec chmod 755 {} \;

# Cleanup
rm -rf $MODPATH/jni
rm -rf $MODPATH/libs

ui_print "- Modul berhasil diinstal"
ui_print "- Restart perangkat Anda untuk mengaktifkan modul"
