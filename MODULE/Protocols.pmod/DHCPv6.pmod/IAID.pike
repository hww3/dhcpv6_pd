string iaid;
 
protected variant void create() {}

protected variant void create(string _iaid) {
  iaid = _iaid;
}

mixed _encode() {
  return (["iaid" : iaid]);
}

mixed _decode(mixed x) {
  iaid = x->iaid;
}

string encode() {
  return sprintf("%04s", iaid);
}

protected int(0..1) _equal(mixed other) {
  return objectp(other) && other->iaid == iaid;
}

protected int(0..1) `==(mixed other) {
  return objectp(other) && other->iaid == iaid;
}

protected int _hash() {
  return hash(iaid);
}
