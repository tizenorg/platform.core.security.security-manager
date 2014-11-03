CONFIGURE_FILE(security-manager.service.in security-manager.service @ONLY)

INSTALL(FILES
    security-manager.service
    security-manager.target
    security-manager.socket
    security-manager-master.socket
    DESTINATION
    ${SYSTEMD_INSTALL_DIR}
)
