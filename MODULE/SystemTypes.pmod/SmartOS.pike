import Protocols.DHCPv6;

inherit .Generic;

string ndpdconffile = "/etc/inet/ndpd.conf";

string get_identifier() {
  return Standards.JSON.decode(Process.popen("sysinfo"))->UUID;
}

void prefix_acquired(IA_PDOption allocation, int has_changed, IA_PDOption old_allocation) {
werror("prefix_acquired(%O, %O, %O)\n", allocation, has_changed, old_allocation);

// TODO we need to come up with a better mechanism for writing configuration.
   string conf = Stdio.read_file(ndpdconffile);
   int must_add;
   int must_remove;
werror("Old conf: %O\n", conf);
   if(search(conf, "\nprefix " + allocation->address + "/" + allocation->prefix) == -1 || has_changed)
     must_add = 1;
   if(old_allocation && has_changed) must_remove = 1;


   if(must_remove) {
      string searchstring = "\nprefix " + old_allocation->address + "/" + old_allocation->prefix;
      int start = search(conf, searchstring);
      if(start != -1) {
         int end = search(conf, "\n", start + sizeof(searchstring));
         if(start != 0) conf = conf[0.. start-1];
         if(end != -1) conf = conf[end+1 ..];
      }
   }

   if(must_add) {
      conf+="\nprefix " + allocation->address + "/" + allocation->prefix + " " + config->downstream_interface + " AdvOnLinkFlag on AdvAutonomousFlag on AdvPreferredLifetime " + allocation->preferred_lifetime + " AdvValidLifetime " + allocation->valid_lifetime + "\n";
   }

   if(must_add || must_remove) {

      string searchstring = "\nif " + config->downstream_interface + " AdvSendAdvertisements";
      int start = search(conf, searchstring);
      if(start != -1) {
         int end = search(conf, "\n", start + sizeof(searchstring));
         if(start != 0) conf = conf[0.. start-1];
         if(end != -1) conf = conf[end+1 ..];
      }
      conf += "\nif " + config->downstream_interface + " AdvSendAdvertisements on\n";

     werror("conf file: %O\n", conf);
     Stdio.write_file(ndpdconffile, conf);
     Process.popen("/usr/sbin/svcadm restart ndp");
  }
}

void prefix_abandoned(IA_PDOption allocation) {

}


