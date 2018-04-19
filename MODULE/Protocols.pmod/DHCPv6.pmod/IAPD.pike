inherit .DHCPOption;

constant option_type = 25;
.IAID iaid;
int t1;
int t2;

array options;
multiset(int) option_types = (<>);

mixed _encode() {
  return (["t1": t1, "t2": t2, "iaid": iaid, "options": options]);
}

mixed _decode(mixed x) {
  t1 = x->t1;
  t2 = x->t2;
  iaid = x->iaid;
  options = x->options;
  register_options();
}

protected variant void create(.IAID _iaid, int t1_secs, int t2_secs, array _options) {
  iaid = _iaid;
  t1 = t1_secs;
  t2 = t2_secs;
  options = _options;
  register_options();
}

void register_options() {
  foreach(options;; object option) 
    option_types[option->option_type] = 1;
}

protected void encode_body(Stdio.Buffer buf) {
  buf->add(iaid->encode());
  buf->add_int(t1, 4);
  buf->add_int(t2, 4);
  foreach(options;; object option) {
werror("OPTION: %O", option);
mixed e = option->encode(); 
werror(" => %O\n", e);
     buf->add(e);
  }
}

protected void decode_body(Stdio.Buffer buf) {
werror("parsing IAPD\n");
  iaid = .IAID(buf->read(4));
  t1 = buf->read_int(4);
  t2 = buf->read_int(4);

  options = ({});
  object option;

  while(sizeof(buf)) {
    option = decode_pd_option(buf);
 
    if(option) {
      options +=({option});
      option_types[option->option_type] = 1;
    }
  }
}

object decode_pd_option(Stdio.Buffer buf) {
//  object rk = buf->rewind_key();

  int pd_type = buf->read_int(2);

  if(pd_type != .OPTION_IA_PDOPTION) {
     throw(Error.Generic("Received invalid IA_PD option type " + pd_type +".\n"));
  }
//  rk->rewind();
//  rk = 0;

  object option = .IA_PDOption(buf->read_hstring(2));
  return option;
}

int(0..1) has_option(int option_type) {
  return option_types[option_type];
}

.DHCPOption get_option(int option_type) {
  foreach(options;; .DHCPOption option)
    if(option->option_type == option_type) return option;

  return 0;
}
