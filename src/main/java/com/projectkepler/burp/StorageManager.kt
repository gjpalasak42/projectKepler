package com.projectkepler.burp

import burp.api.montoya.logging.Logging
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import java.io.*
import java.lang.reflect.Type

/**
 * Manages persistence of attack data and configuration.
 * Why: Centralizing storage logic ensures thread-safe access to the JSON files
 * and provides a caching layer to minimize disk I/O during UI refreshes.
 */
class StorageManager(
    storagePath: String,
    configPath: String,
    private val logging: Logging?
) {
    private val storageFile = File(storagePath)
    private val configFile = File(configPath)
    private val gson = GsonBuilder().setPrettyPrinting().create()

    private var lastLoadedTime: Long = 0
    private var cachedAttacks: MutableList<AttackEntry>? = null

    @Synchronized
    fun saveAttack(entry: AttackEntry) {
        val attacks = loadAttacks()
        attacks.add(entry)
        saveAll(attacks)
    }

    @Synchronized

    fun updateAttack(entry: AttackEntry) {
        val attacks = loadAttacks()
        val index = attacks.indexOfFirst { it.id == entry.id }
        if (index != -1) {
            attacks[index] = entry
            saveAll(attacks)
        }
    }

    /**
     * Loads attacks from disk with a caching strategy based on file modification time.
     * Why: Burp UI can trigger multiple refreshes; caching prevents redundant parsing of potentially large JSON files.
     */
    @Synchronized
    fun loadAttacks(): MutableList<AttackEntry> {
        if (!storageFile.exists()) {
            return mutableListOf<AttackEntry>().also { cachedAttacks = it }
        }

        val lastModified = storageFile.lastModified()
        cachedAttacks?.let {
            if (lastModified <= lastLoadedTime) {
                return it.toMutableList()
            }
        }

        return try {
            FileReader(storageFile).use { reader ->
                val mapListType: Type = object : TypeToken<ArrayList<Map<String, Any?>>>() {}.type
                val attackMaps: MutableList<Map<String, Any?>>? = gson.fromJson(reader, mapListType)

                var modified = false
                attackMaps?.forEach { map ->
                    @Suppress("UNCHECKED_CAST")
                    val mutableMap = map as? MutableMap<String, Any?> ?: return@forEach
                    if (mutableMap["id"] == null || (mutableMap["id"] as? String).isNullOrBlank()) {
                        mutableMap["id"] = java.util.UUID.randomUUID().toString()
                        modified = true
                    }
                }

                val attacks: MutableList<AttackEntry> = if (attackMaps != null) {
                    val attacksJson = gson.toJson(attackMaps)
                    val attackListType: Type = object : TypeToken<ArrayList<AttackEntry>>() {}.type
                    gson.fromJson<ArrayList<AttackEntry>>(attacksJson, attackListType) ?: mutableListOf()
                } else {
                    mutableListOf()
                }

                if (modified) {
                    saveAll(attacks)
                }

                attacks.also { attackList ->
                    cachedAttacks = attackList.toMutableList()
                    lastLoadedTime = storageFile.lastModified()
                }
            }
        } catch (e: IOException) {
            logging?.logToError("Error loading attacks: ${e.message}")
            mutableListOf()
        }
    }

    @Synchronized
    fun deleteAttacks(ids: Set<String>, permanent: Boolean): List<AttackEntry> {
        val allAttacks = loadAttacks()
        var changed = false

        if (permanent) {
            changed = allAttacks.removeIf { it.id in ids }
        } else {
            allAttacks.forEach { attack ->
                if (attack.id in ids && !attack.deleted) {
                    attack.deleted = true
                    changed = true
                }
            }
        }

        if (changed) saveAll(allAttacks)
        return allAttacks
    }

    @Synchronized
    fun restoreAttacks(ids: Set<String>): List<AttackEntry> {
        val allAttacks = loadAttacks()
        var changed = false

        allAttacks.forEach { attack ->
            if (attack.id in ids && attack.deleted) {
                attack.deleted = false
                changed = true
            }
        }

        if (changed) saveAll(allAttacks)
        return allAttacks
    }

    @Synchronized
    fun emptyTrash(): List<AttackEntry> {
        val allAttacks = loadAttacks()
        if (allAttacks.removeIf { it.deleted }) {
            saveAll(allAttacks)
        }
        return allAttacks
    }

    private fun saveAll(attacks: List<AttackEntry>) {
        try {
            FileWriter(storageFile).use { writer ->
                gson.toJson(attacks, writer)
                lastLoadedTime = storageFile.lastModified()
                cachedAttacks = attacks.toMutableList()
            }
        } catch (e: IOException) {
            logging?.logToError("Error saving attacks: ${e.message}")
        }
    }

    @Synchronized
    fun saveConfig(config: ExtensionConfig) {
        try {
            FileWriter(configFile).use { writer -> gson.toJson(config, writer) }
        } catch (e: IOException) {
            logging?.logToError("Error saving config: ${e.message}")
        }
    }

    @Synchronized
    fun loadConfig(): ExtensionConfig {
        if (!configFile.exists()) return ExtensionConfig()

        return try {
            FileReader(configFile).use { reader ->
                gson.fromJson(reader, ExtensionConfig::class.java) ?: ExtensionConfig()
            }
        } catch (e: IOException) {
            logging?.logToError("Error loading config: ${e.message}")
            ExtensionConfig()
        }
    }

    @Synchronized
    @Throws(IOException::class)
    fun exportAttacks(destination: File) {
        val attacks = loadAttacks()
        FileWriter(destination).use { writer -> gson.toJson(attacks, writer) }
    }

    @Synchronized
    @Throws(IOException::class)
    fun importAttacks(source: File) {
        if (!source.exists()) throw FileNotFoundException("Import file not found: ${source.absolutePath}")

        FileReader(source).use { reader ->
            val mapListType: Type = object : TypeToken<ArrayList<Map<String, Any?>>>() {}.type
            val attackMaps: MutableList<Map<String, Any?>>? = gson.fromJson(reader, mapListType)

            attackMaps?.forEach { map ->
                @Suppress("UNCHECKED_CAST")
                val mutableMap = map as? MutableMap<String, Any?> ?: return@forEach
                if (mutableMap["id"] == null || (mutableMap["id"] as? String).isNullOrBlank()) {
                    mutableMap["id"] = java.util.UUID.randomUUID().toString()
                }
            }

            val importedAttacks: List<AttackEntry> = if (attackMaps != null) {
                val attacksJson = gson.toJson(attackMaps)
                val attackListType: Type = object : TypeToken<ArrayList<AttackEntry>>() {}.type
                gson.fromJson<ArrayList<AttackEntry>>(attacksJson, attackListType) ?: emptyList()
            } else {
                emptyList()
            }

            if (importedAttacks.isNotEmpty()) {
                val currentAttacks = loadAttacks()
                val existingIds = currentAttacks.map { entry -> entry.id }.toSet()

                val uniqueNewAttacks = importedAttacks.filter { entry -> entry.id !in existingIds }

                if (uniqueNewAttacks.isNotEmpty()) {
                    currentAttacks.addAll(uniqueNewAttacks)
                    saveAll(currentAttacks)
                }
            }
        }
    }
}
