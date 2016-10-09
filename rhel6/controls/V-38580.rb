# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38580 - The audit system must be configured to audit the loading and unloading of dynamic kernel modules.'

control 'V-38580' do
  impact 0.5
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc '
The addition/removal of kernel modules can be used to alter the behavior of the kernel and potentially introduce malicious code into kernel space. It is important to have an audit trail of modules that have been introduced into the kernel.
'
  tag 'stig','V-38580'
  tag severity: 'medium'
  tag checkid: 'C-46138r3_chk'
  tag fixid: 'F-43528r2_fix'
  tag version: 'RHEL-06-000202'
  tag ruleid: 'SV-50381r2_rule'
  tag fixtext: '
Add the following to "/etc/audit/audit.rules" in order to capture kernel module loading and unloading events, setting ARCH to either b32 or b64 as appropriate for your system:

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=[ARCH] -S init_module -S delete_module -k modules
'
  tag checktext: '
To determine if the system is configured to audit execution of module management programs, run the following commands:

$ sudo egrep -e "(-w |-F path=)/sbin/insmod" /etc/audit/audit.rules
$ sudo egrep -e "(-w |-F path=)/sbin/rmmod" /etc/audit/audit.rules
$ sudo egrep -e "(-w |-F path=)/sbin/modprobe" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

To determine if the system is configured to audit calls to the "init_module" system call, run the following command:

$ sudo grep -w "init_module" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

To determine if the system is configured to audit calls to the "delete_module" system call, run the following command:

$ sudo grep -w "delete_module" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

If no line is returned for any of these commands, this is a finding.
'

# START_DESCRIBE V-38580
  [
    '-w /sbin/insmod -p x -k modules',
    '-w /sbin/rmmod -p x -k modules',
    '-w /sbin/modprobe -p x -k modules'
  ].each do |line|
    describe auditd_rules do
      its('lines') { should include(line) }
    end
  end
  ['init_module','delete_module'].each do |syscall|
    describe auditd_rules.syscall(syscall).action do
      it { should eq(['always']) }
    end
  end
# END_DESCRIBE V-38580

end
