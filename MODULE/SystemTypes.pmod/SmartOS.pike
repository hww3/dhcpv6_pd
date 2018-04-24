import Protocols.DHCPv6;

inherit .Generic;

string preamble = "\n#\n# BEGIN DHCPv6_PD Managed segment\n#\n";
string postamble = "\n#\n# END DHCPv6_PD Managed segment\n#\n";

string ndpdconffile = "/etc/inet/ndpd.conf";

string get_identifier() {
  if(file_stat("/etc/dhcp/duid"))
    return Stdio.read_file("/etc/dhcp/duid");
  else 
    return Standards.JSON.decode(Process.popen("sysinfo"))->UUID;
}

string get_command_segment(string conf) {
  string seg;
  sscanf(conf, "%*s" + preamble + "%s" + postamble + "%*s", seg);
  return seg || "";
}

string remove_command_segment(string conf) {
  string pre, post;
  sscanf(conf, "%s" + preamble + "%*s" + postamble + "%s", pre, post);
  return (pre||"") + (post||"");
}

void prefix_acquired(IA_PDOption allocation, int has_changed, IA_PDOption old_allocation) {
werror("prefix_acquired(%O, %O, %O)\n", allocation, has_changed, old_allocation);

// TODO we need to come up with a better mechanism for writing configuration.
   string conf = Stdio.read_file(ndpdconffile) || "";
   string cs = get_command_segment(conf);
werror("Old conf: %O\n", cs);
   string ncs="\nprefix " + allocation->address + "/" + allocation->prefix + " " + config->downstream_interface + " AdvOnLinkFlag on AdvAutonomousFlag on AdvPreferredLifetime " + allocation->preferred_lifetime + " AdvValidLifetime " + allocation->valid_lifetime + "\n";
   ncs += "\nif " + config->downstream_interface + " AdvSendAdvertisements on\n";


werror("new conf: %O\n", ncs);
   if(ncs != cs) {
     conf = remove_command_segment(conf);
     conf += (preamble + ncs + postamble);
     werror("conf file: %O\n", conf);
     Stdio.write_file(ndpdconffile, conf);
     Process.popen("/usr/sbin/svcadm restart ndp");
  }
}

void prefix_abandoned(IA_PDOption allocation) {
  string conf = Stdio.read_file(ndpdconffile);
  conf = remove_command_segment(conf);
  werror("conf file: %O\n", conf);
     Stdio.write_file(ndpdconffile, conf);
     Process.popen("/usr/sbin/svcadm restart ndp");
}


