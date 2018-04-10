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
