APP_ABI := armeabi-v7a arm64-v8a x86 x86_64
APP_PLATFORM := android-33
APP_STL := c++_static
# Hilangkan -std=c++17 dari APP_CFLAGS!
APP_CFLAGS := -Wall -fpermissive -fexceptions -frtti -DANDROID_R_API=30 -DANDROID_S_API=31 -DANDROID_T_API=33 -DANDROID_U_API=34 -DANDROID_V_API=35
# Jika butuh -std=c++17, tambahkan di Android.mk bagian LOCAL_CPPFLAGS saja