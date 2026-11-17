-- Research SQLite schema, all values public. No wallet secrets or note openings.
CREATE TABLE meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL CHECK(schema_version=3),
 genesis BLOB NOT NULL, genesis_id BLOB NOT NULL CHECK(length(genesis_id)=64), chain BLOB NOT NULL CHECK(length(chain)=32),
 total INTEGER NOT NULL CHECK(total>=0), height INTEGER NOT NULL CHECK(height>=0), head BLOB NOT NULL CHECK(length(head)=64),
 leaf_count INTEGER NOT NULL CHECK(leaf_count BETWEEN 0 AND 1099511627776), root BLOB NOT NULL CHECK(length(root)=64),
 fees INTEGER NOT NULL CHECK(fees>=0), liabilities INTEGER NOT NULL CHECK(liabilities>=0), CHECK(fees+liabilities<=total)
);
CREATE TABLE sources (id BLOB PRIMARY KEY CHECK(length(id)=48), credit INTEGER NOT NULL CHECK(credit>=2116775), public_key BLOB NOT NULL CHECK(length(public_key)=2592), consumed_height INTEGER CHECK(consumed_height>0)) WITHOUT ROWID;
CREATE TABLE nullifiers (id BLOB PRIMARY KEY CHECK(length(id)=64), height INTEGER NOT NULL CHECK(height>0)) WITHOUT ROWID;
CREATE INDEX nullifiers_height ON nullifiers(height);
CREATE TABLE cores (id BLOB PRIMARY KEY CHECK(length(id)=64), height INTEGER NOT NULL CHECK(height>0)) WITHOUT ROWID;
CREATE INDEX cores_height ON cores(height);
CREATE TABLE leaves (idx INTEGER PRIMARY KEY CHECK(idx>=0), origin BLOB NOT NULL CHECK(length(origin)=64), cm BLOB NOT NULL CHECK(length(cm)=64), height INTEGER NOT NULL CHECK(height>0), body_id BLOB NOT NULL CHECK(length(body_id)=64), ordinal INTEGER NOT NULL CHECK(ordinal IN (0,1)), UNIQUE(origin,cm));
CREATE INDEX leaves_height ON leaves(height);
CREATE TABLE nodes (level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 40), idx INTEGER NOT NULL CHECK(idx>=0), value BLOB NOT NULL CHECK(length(value)=64), PRIMARY KEY(level,idx)) WITHOUT ROWID;
CREATE TABLE anchors (height INTEGER PRIMARY KEY CHECK(height>=0), root BLOB NOT NULL CHECK(length(root)=64), leaf_count INTEGER NOT NULL CHECK(leaf_count BETWEEN 0 AND 1099511627776));
CREATE INDEX anchor_pair ON anchors(root,leaf_count);
CREATE TABLE blocks (height INTEGER PRIMARY KEY CHECK(height>0), id BLOB UNIQUE NOT NULL CHECK(length(id)=64), parent BLOB NOT NULL CHECK(length(parent)=64), header BLOB NOT NULL CHECK(length(header)<=8408), leaf_count INTEGER NOT NULL, root BLOB NOT NULL CHECK(length(root)=64), fees INTEGER NOT NULL, liabilities INTEGER NOT NULL, old_count INTEGER NOT NULL, old_root BLOB NOT NULL CHECK(length(old_root)=64), old_fees INTEGER NOT NULL, old_liabilities INTEGER NOT NULL);
CREATE TABLE body_cache (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 catalog_id BLOB NOT NULL CHECK(length(catalog_id)=32),
 hard_bytes INTEGER NOT NULL CHECK(hard_bytes>0),
 cached_bytes INTEGER NOT NULL CHECK(cached_bytes BETWEEN 0 AND hard_bytes),
 unexported_bytes INTEGER NOT NULL CHECK(unexported_bytes BETWEEN 0 AND cached_bytes),
 archive_limit_bytes INTEGER NOT NULL CHECK(archive_limit_bytes>0),
 archive_committed_bytes INTEGER NOT NULL CHECK(archive_committed_bytes BETWEEN 0 AND archive_limit_bytes),
 next_segment INTEGER NOT NULL CHECK(next_segment>=0),
 retention INTEGER NOT NULL CHECK(retention IN (0,1))
);
CREATE TABLE archive_segments (
 segment INTEGER PRIMARY KEY CHECK(segment>=0),
 committed_end INTEGER NOT NULL CHECK(committed_end BETWEEN 0 AND 67108864),
 sealed INTEGER NOT NULL CHECK(sealed IN (0,1))
);
CREATE UNIQUE INDEX archive_one_open ON archive_segments((1)) WHERE sealed=0;
-- Global local-archive catalog: intentionally no FK to canonical blocks/bodies.
-- Rolled-back exported objects remain retained and separately accounted.
CREATE TABLE archive_objects (
 id BLOB PRIMARY KEY CHECK(length(id)=64),
 full_length INTEGER NOT NULL CHECK(full_length BETWEEN 1 AND 2106575),
 segment INTEGER NOT NULL REFERENCES archive_segments(segment) ON DELETE RESTRICT,
 record_offset INTEGER NOT NULL CHECK(record_offset>=148),
 UNIQUE(segment,record_offset)
) WITHOUT ROWID;
-- Replacement for schema1 bodies: same ordered admitted identity/reduced bytes.
CREATE TABLE bodies (
 height INTEGER NOT NULL REFERENCES blocks(height) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 127),
 id BLOB UNIQUE NOT NULL CHECK(length(id)=64),
 full_length INTEGER NOT NULL CHECK(full_length BETWEEN 1 AND 2106575),
 full BLOB CHECK(full IS NULL OR length(full)=full_length),
 reduced BLOB NOT NULL CHECK(length(reduced)<=9499),
 PRIMARY KEY(height,ordinal)
) WITHOUT ROWID;
CREATE INDEX cached_body_order ON bodies(height,ordinal) WHERE full IS NOT NULL;
CREATE TABLE archive_pending (
 height INTEGER NOT NULL, ordinal INTEGER NOT NULL,
 id BLOB UNIQUE NOT NULL CHECK(length(id)=64),
 PRIMARY KEY(height,ordinal),
 FOREIGN KEY(height,ordinal) REFERENCES bodies(height,ordinal) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE TRIGGER body_cache_insert AFTER INSERT ON bodies WHEN NEW.full IS NOT NULL BEGIN
 UPDATE body_cache SET cached_bytes=cached_bytes+NEW.full_length,
  unexported_bytes=unexported_bytes+CASE WHEN retention=1 OR EXISTS(
   SELECT 1 FROM archive_objects WHERE id=NEW.id AND full_length=NEW.full_length
  ) THEN 0 ELSE NEW.full_length END WHERE singleton=1;
 INSERT INTO archive_pending(height,ordinal,id)
  SELECT NEW.height,NEW.ordinal,NEW.id WHERE (SELECT retention FROM body_cache WHERE singleton=1)=0 AND NOT EXISTS(
   SELECT 1 FROM archive_objects WHERE id=NEW.id AND full_length=NEW.full_length);
END;
CREATE TRIGGER body_cache_delete AFTER DELETE ON bodies WHEN OLD.full IS NOT NULL BEGIN
 UPDATE body_cache SET cached_bytes=cached_bytes-OLD.full_length,
  unexported_bytes=unexported_bytes-CASE WHEN retention=1 OR EXISTS(
   SELECT 1 FROM archive_objects WHERE id=OLD.id AND full_length=OLD.full_length
  ) THEN 0 ELSE OLD.full_length END WHERE singleton=1;
END;
CREATE TRIGGER body_identity_immutable BEFORE UPDATE OF height,ordinal,id,full_length,reduced ON bodies BEGIN
 SELECT RAISE(ABORT,'BODY_IDENTITY_IMMUTABLE');
END;
CREATE TRIGGER body_full_only_evict BEFORE UPDATE OF full ON bodies BEGIN
 SELECT CASE WHEN (SELECT retention FROM body_cache WHERE singleton=1)=1 THEN RAISE(ABORT,'RETAIN_EVICTION_PROHIBITED') END;
 SELECT CASE WHEN NOT(OLD.full IS NOT NULL AND NEW.full IS NULL)
  THEN RAISE(ABORT,'CACHE_REFILL_UNSUPPORTED') END;
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM archive_objects
  WHERE id=OLD.id AND full_length=OLD.full_length)
  THEN RAISE(ABORT,'ARCHIVE_REQUIRED') END;
END;
CREATE TRIGGER body_cache_evict AFTER UPDATE OF full ON bodies BEGIN
 UPDATE body_cache SET cached_bytes=cached_bytes-OLD.full_length WHERE singleton=1;
END;
CREATE TRIGGER archive_record_bound BEFORE INSERT ON archive_objects BEGIN
 SELECT CASE WHEN NEW.record_offset+68+NEW.full_length >
  COALESCE((SELECT committed_end FROM archive_segments WHERE segment=NEW.segment),0)
  THEN RAISE(ABORT,'ARCHIVE_RECORD_BOUND') END;
END;
CREATE TRIGGER archive_record_update_bound BEFORE UPDATE OF segment,record_offset ON archive_objects BEGIN
 SELECT CASE WHEN NEW.record_offset+68+NEW.full_length >
  COALESCE((SELECT committed_end FROM archive_segments WHERE segment=NEW.segment),0)
  THEN RAISE(ABORT,'ARCHIVE_RECORD_BOUND') END;
END;
CREATE TRIGGER archive_retain_forbidden BEFORE INSERT ON archive_objects WHEN (SELECT retention FROM body_cache WHERE singleton=1)=1 BEGIN SELECT RAISE(ABORT,'RETAIN_ARCHIVE_PROHIBITED'); END;
CREATE TRIGGER archive_first_ack AFTER INSERT ON archive_objects BEGIN
 UPDATE body_cache SET unexported_bytes=unexported_bytes-COALESCE(
  (SELECT full_length FROM bodies WHERE id=NEW.id AND full_length=NEW.full_length AND full IS NOT NULL),0
 ) WHERE singleton=1;
 DELETE FROM archive_pending WHERE id=NEW.id;
END;
CREATE TRIGGER archive_identity_immutable BEFORE UPDATE OF id,full_length ON archive_objects BEGIN
 SELECT RAISE(ABORT,'ARCHIVE_IDENTITY_IMMUTABLE');
END;
-- Rust reserve() under existing BEGIN IMMEDIATE checks used+incoming<=hard
-- BEFORE any admission mutation, returning typed ArchiveBacklog on shortage.
-- The CHECK is a second invariant, not a substitute for that typed precheck.
-- Rust alone installs catalog rows after verified fsync; no JSON ACK API.
-- No automatic catalog deletion/segment GC or full-cache refill is proposed.
CREATE TRIGGER archive_no_implicit_gc BEFORE DELETE ON archive_objects BEGIN
 SELECT RAISE(ABORT,'ARCHIVE_GC_UNSUPPORTED');
END;
CREATE TRIGGER archive_end_monotonic BEFORE UPDATE OF committed_end ON archive_segments
 WHEN NEW.committed_end<OLD.committed_end BEGIN
 SELECT RAISE(ABORT,'ARCHIVE_END_REGRESSION');
END;
CREATE TRIGGER archive_bytes AFTER UPDATE OF committed_end ON archive_segments BEGIN
 UPDATE body_cache SET archive_committed_bytes=archive_committed_bytes+
  NEW.committed_end-OLD.committed_end WHERE singleton=1;
END;
CREATE TRIGGER archive_segments_no_gc BEFORE DELETE ON archive_segments BEGIN
 SELECT RAISE(ABORT,'ARCHIVE_GC_UNSUPPORTED');
END;
-- Catalog ID is immutable; cloning/replacing DB requires separate operator rebind.
CREATE TRIGGER catalog_id_immutable BEFORE UPDATE OF catalog_id ON body_cache BEGIN
 SELECT RAISE(ABORT,'CATALOG_ID_IMMUTABLE');
END;

CREATE TABLE node_undo (height INTEGER NOT NULL, level INTEGER NOT NULL, idx INTEGER NOT NULL, old_value BLOB CHECK(old_value IS NULL OR length(old_value)=64), PRIMARY KEY(height,level,idx)) WITHOUT ROWID;
CREATE INDEX node_undo_lookup ON node_undo(level,idx,height);

-- Local retention policy is fixed for this store; changing it needs an explicit rebuild/migration.
CREATE TRIGGER retention_immutable BEFORE UPDATE OF retention ON body_cache WHEN NEW.retention!=OLD.retention BEGIN SELECT RAISE(ABORT,'RETENTION_POLICY_IMMUTABLE'); END;
CREATE TRIGGER retain_segments_forbidden BEFORE INSERT ON archive_segments WHEN (SELECT retention FROM body_cache WHERE singleton=1)=1 BEGIN SELECT RAISE(ABORT,'RETAIN_ARCHIVE_PROHIBITED'); END;
