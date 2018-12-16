JFLAGS = -g
JC = javac
.SUFFIXES: .java .class
.java.class:
        $(JC) $(JFLAGS) $src.edu.wisc.cs.sdn.simpledns.SimpleDNS.java

CLASSES = \
        src.edu.wisc.cs.sdn.simpledns.SimpleDNS.java \
        src.edu.wisc.cs.sdn.simpledns.packet.DNS.java \
        src.edu.wisc.cs.sdn.simpledns.packet.DNSQuestion.java \
        src.edu.wisc.cs.sdn.simpledns.packet.DNSRdata.java \
        src.edu.wisc.cs.sdn.simpledns.packet.DNSRdataAddress.java \
        src.edu.wisc.cs.sdn.simpledns.packet.DNSRdataBytes.java \
        src.edu.wisc.cs.sdn.simpledns.packet.DNSRdataName.java \
        src.edu.wisc.cs.sdn.simpledns.packet.DNSRdataString.java \
        src.edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord.java


default: classes

classes: $(CLASSES:.java=.class)

clean:
        $(RM) *.class