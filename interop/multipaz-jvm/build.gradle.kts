plugins {
    kotlin("jvm") version "2.2.21"
}
repositories { mavenCentral() }
dependencies {
    implementation("org.multipaz:multipaz-jvm:0.99.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation(kotlin("test"))
}
// 稼働 JDK（Homebrew openjdk）をそのまま使う。bytecode は 17 を狙う（Kotlin/JUnit 互換）
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
tasks.test { useJUnitPlatform(); testLogging { showStandardStreams = true; events("passed", "failed", "skipped") } }
