SET(TARGET_DB ".security-manager.db")

SET(SHARE_DIR "${DATA_INSTALL_DIR}/security-manager")
SET(DB_SCRIPT_DIR "${SHARE_DIR}/db")
SET(FOTA_DIR "${TZ_SYS_ETC}/opt/upgrade")

ADD_CUSTOM_COMMAND(
    OUTPUT ${TARGET_DB} ${TARGET_DB}-journal
    COMMAND sqlite3 ${TARGET_DB} <db.sql
    )

# Add a dummy build target to trigger building of ${TARGET_DB}
ADD_CUSTOM_TARGET(DB ALL DEPENDS ${TARGET_DB})

# Update scrpipts
INSTALL(FILES update.sh DESTINATION ${DB_SCRIPT_DIR})
INSTALL(DIRECTORY updates DESTINATION ${DB_SCRIPT_DIR})
INSTALL(FILES db.sql DESTINATION ${DB_SCRIPT_DIR})

# FOTA updater
INSTALL(FILES 240.security-manager.db-update.sh DESTINATION ${FOTA_DIR})

# The database itself
INSTALL(FILES ${TARGET_DB} DESTINATION ${DB_INSTALL_DIR})
INSTALL(FILES ${TARGET_DB}-journal DESTINATION ${DB_INSTALL_DIR})
