string iaid;

protected variant void create(string _iaid) {
  iaid = _iaid;
}

string encode() {
  return sprintf("%04s", iaid);
}
