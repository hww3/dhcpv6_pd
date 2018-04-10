inherit .DHCPOption;
constant IA_PD_OPTION = 26;

constant option_type = 25;
.IAID iaid;
int t1;
int t2;

array options;

protected variant void create(.IAID _iaid, int t1_secs, int t2_secs, array _options) {
  iaid = _iaid;
  t1 = t1_secs;
  t2 = t2_secs;
  options = _options;
}

protected void encode_body(Stdio.Buffer buf) {
  buf->add(iaid->encode());
  buf->add_int(t1, 4);
  buf->add_int(t2, 4);
  foreach(options;; object option) {
mixed e = option->encode();
werror("OPTION: %O => %O\n", option, e);
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
 
    if(option) options +=({option});
  }
}

object decode_pd_option(Stdio.Buffer buf) {
//  object rk = buf->rewind_key();

  int pd_type = buf->read_int(2);

  if(pd_type != IA_PD_OPTION) {
     throw(Error.Generic("Received invalid IA_PD option type " + pd_type +".\n"));
  }
//  rk->rewind();
//  rk = 0;

  object option = .IA_PDOption(buf->read_hstring(2));
  return option;
}
