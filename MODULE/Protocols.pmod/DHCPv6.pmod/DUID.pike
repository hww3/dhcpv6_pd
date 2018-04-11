string duid;

protected variant void create(string _duid) {
  duid = _duid;
}

// Generate a DUID Assigned by Vendor Based on Enterprise Number [DUID-EN]
protected variant void create(int enterprise_num, string enterprise_id) {
  if(!enterprise_num) enterprise_num = 13047; // Welliver enterprises
  duid = sprintf("%2c%4c%s", 2, enterprise_num, enterprise_id);
}

string encode() {
  return duid;
}

mixed _encode() {
werror("_encode\n");
  return (["duid": duid]);
}

void _decode(mixed x) {
werror("decode: %O\n", x);
  duid = x->duid;
}

protected int(0..1) _equal(mixed other) {
  return objectp(other) && other->duid == duid;
}

protected int(0..1) `==(mixed other) {
  return objectp(other) && other->duid == duid;
}
