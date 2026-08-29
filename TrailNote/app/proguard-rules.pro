# Security Container Plant hardened build rules.
# Keep Android entry points, while allowing R8 to rename and optimize internal security classes.
-keep public class * extends android.app.Activity

# Remove source file names from hardened stack traces and avoid exposing local source layout.
-renamesourcefileattribute SCP

# Preserve only runtime annotations Android may require.
-keepattributes RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations,AnnotationDefault

# Strip ordinary logging calls if any are introduced later.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}
