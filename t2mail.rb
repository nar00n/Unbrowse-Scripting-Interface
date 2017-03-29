require 'rubygems' if RUBY_VERSION.split('.')[1].to_i < 9
require 'tmail'
require 'win32ole'
require 'net/smtp'

# Unbrowse SNMP Scripting Interface Demo 
# by Vipin.K.Narayanan
#
# t2email -    	start, stop, and control the unbrowse trap 
#            	passive receiver. forwards all traps to email
#
#
# Licensing
#   You can use this in any way you please. No warranties.
#   (c) Unleash Networks 2009, All rights reserved
# ---------------------------------------------------------------

raise "USAGE: ruby #{$0}" unless ARGV.size == 0

# Change this to your environment
server_settings = {
	:server => "mail.xyz.com",
	:port => 25,
	:username => "username@xyz.com",
	:domain => 'localhost',
	:password => 'PekingDucky0011'}

# Add from,to,and cc
mail_settings = {
	:from => "unbrowse_snmp_traps",
	:to => "vivekfortraps@gmail.com",
	:cc => "" 
	}

# Max Mail frequency seconds
mail_frequency_seconds  = 30

# ---------------------------------------------------
# 
#	Dumps almost all trap information onto screen
# ---------------------------------------------------
def pr_trap(one_trap)
	tss = ""
	
	# --------------------------
	# Print all trap information 
	# --------------------------
	tss << " --Trap from Unbrowse SNMP -------------------\n" 
	tss << " Trap ID    : #{one_trap.ID}\n"
	tss << " From Agent : #{one_trap.AgentAddress}\n"
	tss << " To Manager : #{one_trap.DestinationAddress}\n"
	tss << " Timestamp  : #{one_trap.TimestampLocal}\n"
	tss << " User/Comm  : #{one_trap.UserCommunity}\n"
	tss << " Varbinds   : #{one_trap.VarbindCount}\n"
	tss << " OID        : #{one_trap.EffectiveTrapOID}\n"


	# --------------------------
	# Print all varbinds in trap
	# --------------------------
	tss << " --------- Varbind list ----------\n" 
	(0 .. one_trap.VarbindCount - 1).each do |i|
		one_varbind = one_trap.GetVarbindByIdx(i)
		tss << "\t #{one_varbind.OID}   =  #{one_varbind.Value}\n"
	end
	tss << " ------------------------------------------\n" 

	return tss
end

def mail_this(subject,body,mopts,svropts)

        #create the mail object
        mail = TMail::Mail.new
        mail.date = Time.now
        mail.from = mopts[:from]
        mail.to = mopts[:to]
        mail.cc = mopts[:cc]
        mail.subject = subject
        mail.body = body
        mail.mime_version = '1.0'
        m_msg = mail.encoded
        
        #connect to the SMTP server and send mail
        begin
			Net::SMTP.start(svropts[:server],svropts[:port],svropts[:domain],
						    svropts[:username],svropts[:password],:login) do |smtp|
				 smtp.send_mail m_msg, mail.from_addrs, mail.destinations
			end
        rescue Exception => e
            p "Unable to send mail " + e.message
        end

	p "Sent email at " + Time.now.to_s
end

# --------------------------------------------------
# Create the trap server  and attach the events 
# --------------------------------------------------
rep_mgr = WIN32OLE.new("UnbrowseSNMP.RepositoryManager")
rep_db  = rep_mgr.LoadRepositoryReadOnly
trap_mgr = WIN32OLE.new("UnbrowseSNMP.TrapReceiver")
puts "Loaded the Unbrowse SNMP Trap Server" 


# --------------------------------------------------
# Use the UDP Server mode (other options are Winpcap and Raw Sockets)
# --------------------------------------------------
trap_mgr.UDPServerMode = true


# --------------------------------------------------
# Open a new database - you can save this later
# --------------------------------------------------
trap_mgr.NewBufferDatabase 

# --------------------------------------------------
# Start the passive trap receiver
# --------------------------------------------------
puts "Starting .." 
stopping="false"
trap_mgr.Start 
puts "Listening for traps .." 

# ------------------------------------------------------
# Enter into an loop, checking the buffer every 1 second 
# after sending emails, we delete the trap from the buffer
# This frees up memory
# ------------------------------------------------------
last_processed = 0
begin
while true
	 trap_text = ""
     end_id  = trap_mgr.TrapCount
	 (last_processed..end_id-1).each do |tid|
         trap_text << pr_trap(trap_mgr.GetTrapByIdx(tid))
		 trap_mgr.DeleteTrapByIdx(tid-1)
	 end
     last_processed = end_id
     
     # send email out
     unless trap_text.empty?
		mail_this("Unbrowse SNMP Trap report", trap_text, mail_settings, server_settings)
	 end

     sleep(mail_frequency_seconds)
end
rescue
end



# --------------------------------------------------
# Stop the trap receiver 
# --------------------------------------------------
puts "stopping the trap receiver"
trap_mgr.Stop

