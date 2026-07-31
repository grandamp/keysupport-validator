# Keep the serialization classes for VSS API
-keepattributes RuntimeVisibleAnnotations, AnnotationDefault
-keep class net.keysupport.validator.data.** { *; }
-keep @kotlinx.serialization.Serializable class * { *; }
