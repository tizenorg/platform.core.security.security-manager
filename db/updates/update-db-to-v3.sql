PRAGMA foreign_keys = OFF;
BEGIN EXCLUSIVE TRANSACTION;

PRAGMA user_version = 3;

-- Tables
ALTER TABLE pkg ADD COLUMN author_id INTEGER REFERENCES author (author_id);

DROP TABLE IF EXISTS app_new;
CREATE TABLE app_new (
app_id INTEGER PRIMARY KEY,
pkg_id INTEGER NOT NULL,
uid INTEGER NOT NULL,
name VARCHAR NOT NULL,
version VARCHAR NOT NULL,
UNIQUE (name, uid),
FOREIGN KEY (pkg_id) REFERENCES pkg (pkg_id)
);

INSERT INTO app_new SELECT app_id, pkg_id, uid, name, version FROM app;

-- TODO this will ignore all other authors of given pkg apps except 1st one. Maybe the migration should fail in such case?
UPDATE pkg SET author_id = (SELECT author_id FROM app_pkg_view WHERE author_id IS NOT NULL LIMIT 1);

DROP TABLE app;
ALTER TABLE app_new RENAME TO app;

-- Views
DROP VIEW IF EXISTS app_pkg_view;
CREATE VIEW app_pkg_view AS
SELECT
    app.app_id,
    app.name as app_name,
    app.pkg_id,
    app.uid,
    pkg.name as pkg_name,
    app.version as version,
    pkg.author_id,
    author.name as author_name
FROM app
LEFT JOIN pkg USING (pkg_id)
LEFT JOIN author USING (author_id);

-- Triggers
DROP TRIGGER IF EXISTS app_pkg_view_insert_trigger;
CREATE TRIGGER app_pkg_view_insert_trigger
INSTEAD OF INSERT ON app_pkg_view
BEGIN
    SELECT RAISE(ABORT, 'Another application from this package is already installed with different author')
        WHERE EXISTS (SELECT 1 FROM app_pkg_view
                      WHERE pkg_name=NEW.pkg_name
                      AND author_name IS NOT NULL
                      AND NEW.author_name IS NOT NULL
                      AND author_name!=NEW.author_name);

    INSERT OR IGNORE INTO author(name) VALUES (NEW.author_name);
    INSERT OR IGNORE INTO pkg(name, author_id) VALUES (
        NEW.pkg_name,
        (SELECT author_id FROM author WHERE name=NEW.author_name));
    -- If pkg have already existed with empty author do update it
    UPDATE pkg SET author_id=(SELECT author_id FROM author WHERE name=NEW.author_name) WHERE name=NEW.pkg_name AND author_id IS NULL;
    INSERT OR IGNORE INTO app(pkg_id, name, uid, version) VALUES (
        (SELECT pkg_id FROM pkg WHERE name=NEW.pkg_name),
        NEW.app_name,
        NEW.uid,
        NEW.version);
END;

DROP TRIGGER IF EXISTS app_pkg_view_delete_trigger;
CREATE TRIGGER app_pkg_view_delete_trigger
INSTEAD OF DELETE ON app_pkg_view
BEGIN
    DELETE FROM app WHERE app_id=OLD.app_id AND uid=OLD.uid;
    DELETE FROM pkg WHERE pkg_id NOT IN (SELECT DISTINCT pkg_id from app);
    DELETE FROM author WHERE author_id NOT IN (SELECT DISTINCT author_id FROM pkg WHERE author_id IS NOT NULL);
END;


COMMIT TRANSACTION;
PRAGMA foreign_keys = ON;
