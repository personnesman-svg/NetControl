package com.netcontrol.app.data

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface RuleDao {
    @Query("SELECT * FROM firewall_rules ORDER BY priority ASC, id ASC")
    fun observeRules(): Flow<List<RuleEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(rule: RuleEntity): Long

    @Update
    suspend fun update(rule: RuleEntity)

    @Delete
    suspend fun delete(rule: RuleEntity)
}

@Dao
interface DiagnosticEventDao {
    @Query("SELECT * FROM diagnostic_events ORDER BY timestampMs DESC LIMIT 300")
    fun observeLatest(): Flow<List<DiagnosticEventEntity>>

    @Insert
    suspend fun insert(event: DiagnosticEventEntity)

    @Query("DELETE FROM diagnostic_events")
    suspend fun clear()

    @Query("DELETE FROM diagnostic_events WHERE id NOT IN (SELECT id FROM diagnostic_events ORDER BY timestampMs DESC LIMIT 300)")
    suspend fun trimToLimit()
}

@Database(entities = [RuleEntity::class, DiagnosticEventEntity::class], version = 1, exportSchema = true)
abstract class NetControlDatabase : RoomDatabase() {
    abstract fun ruleDao(): RuleDao
    abstract fun eventDao(): DiagnosticEventDao

    companion object {
        @Volatile private var instance: NetControlDatabase? = null

        fun get(context: Context): NetControlDatabase = instance ?: synchronized(this) {
            instance ?: Room.databaseBuilder(
                context.applicationContext,
                NetControlDatabase::class.java,
                "netcontrol.db",
            ).build().also { instance = it }
        }
    }
}
