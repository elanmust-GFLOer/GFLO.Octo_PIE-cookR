\set ON_ERROR_STOP on
SELECT current_user,current_database();
SELECT rolname,
 has_schema_privilege(rolname,'private','USAGE') AS private_usage,
 has_table_privilege(rolname,'private.wallet_binding_state','SELECT') AS state_select,
 has_table_privilege(rolname,'private.wallet_bindings','INSERT') AS binding_insert
 FROM pg_roles WHERE rolname IN ('postgres','b23r3_data_owner','b23r3_mutator','b23r3_lab_caller','b23_runtime','b23_untrusted') ORDER BY rolname;
SELECT c.conname,c.conrelid::regclass AS referencing_table,c.confrelid::regclass AS referenced_table,
 cc.relowner::regrole AS ref_owner, pp.relowner::regrole AS target_owner
 FROM pg_constraint c JOIN pg_class cc ON c.conrelid=cc.oid JOIN pg_class pp ON c.confrelid=pp.oid
 WHERE c.contype='f' AND c.connamespace='private'::regnamespace ORDER BY c.conname;
