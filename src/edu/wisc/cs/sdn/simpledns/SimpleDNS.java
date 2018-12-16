package edu.wisc.cs.sdn.simpledns;

import edu.wisc.cs.sdn.simpledns.packet.*;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.regex.Pattern;

public class SimpleDNS
{
	private static String serverIP;
	private static Map<String, String> ec2Table;
	private static DatagramSocket serverSocket;
	private final static int RECEIVE_DNS_PORT = 8053;
	private final static int SEND_DNS_PORT = 53;
	private final static int MAX_PACKET_SIZE = 4000;

	public static void main(String[] args) {
		System.out.println("Hello, DNS!");


		if (args.length != 4) {
			System.out.println("Invalid Arguments!");
			return;
		}
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-r")) {
				serverIP = args[++i];
			} else if (args[i].equals("-e")) {
				ec2Table = loadEC2Table(args[++i]);
			} else {
				System.out.println("Invalid Arguments!");
				return;
			}
			// open a socket
			startDnsServer(serverIP);
		}
	}

	private static void startDnsServer(String serverIP){

		byte[] buffer = new byte[MAX_PACKET_SIZE];
		DNS dnsPacket;
		DNSQuestion question;

		try {
			serverSocket = new DatagramSocket(RECEIVE_DNS_PORT);
			System.out.println("Socket initialization succeeded, listening...");
			while(true){
				DatagramPacket dnsReceived = new DatagramPacket(buffer, buffer.length);
				serverSocket.receive(dnsReceived);
				dnsPacket = DNS.deserialize(buffer, buffer.length);
				if (dnsPacket.getOpcode() != DNS.OPCODE_STANDARD_QUERY){
					// Only listening to standard queries
					continue;
				}
				question = dnsPacket.getQuestions().get(0);
				Short[] validTypes = {DNS.TYPE_A, DNS.TYPE_AAAA, DNS.TYPE_CNAME, DNS.TYPE_NS};
				Set<Short> validDnsTypes = new HashSet<Short>(Arrays.asList(validTypes));
				if (!validDnsTypes.contains(question.getType())){
					continue;
				}
				handleDnsQuery(dnsPacket, serverIP, dnsReceived);
			}
		} catch (SocketException e) {
			System.out.println("Server socket initialization failed!");
			e.printStackTrace();
			serverSocket.close();
			System.exit(1);
		} catch (IOException i) {
			i.printStackTrace();
			serverSocket.close();
			System.exit(1);
		}
		serverSocket.close();
	}

	private static void handleDnsQuery(DNS dnsPacket, String serverIP, DatagramPacket dnsReceived) throws IOException, UnknownHostException, SocketException {
		// Check NS then reply to client, if in EC2, add a TXT record to reply
		byte[] packet = new byte[MAX_PACKET_SIZE];
		DatagramPacket query;
		InetAddress ipAddress = InetAddress.getByName(serverIP);
		DatagramSocket socket = new DatagramSocket(SEND_DNS_PORT);
		DNS toSendToClient = dnsPacket;

		while(true){
			query = new DatagramPacket(dnsPacket.serialize(), 0, dnsPacket.getLength(), ipAddress, SEND_DNS_PORT);
			// This socket is used to send query
			socket.send(query);
			socket.receive(new DatagramPacket(packet, packet.length));
			dnsPacket = DNS.deserialize(packet, packet.length);
			if(!dnsPacket.isRecursionDesired()){
				// Send back to client
				sendDNSReply(dnsPacket, dnsReceived);
				break;
			} else {
				dnsPacket.setQuery(true);
				for (DNSResourceRecord additional : dnsPacket.getAdditional()){
					if(additional.getType() == DNS.TYPE_AAAA || additional.getType() == DNS.TYPE_A){
						DNSRdataAddress address = (DNSRdataAddress) additional.getData();
						String addressString = address.toString();
						ipAddress = InetAddress.getByName(addressString);
						break;
					}
				}
				SimpleDNS.addAnsToReply(dnsPacket, toSendToClient);
				if(dnsPacket.getAnswers().size() > 0){
					for (DNSResourceRecord record : dnsPacket.getAnswers()){
						toSendToClient.addAnswer(record);
					}
					sendDNSReply(toSendToClient, dnsReceived);
					break;
				}
			}
			SimpleDNS.removeEntryFromQuery(dnsPacket);
		}
		socket.close();
	}

	private static void removeEntryFromQuery(DNS dnsPacket){
		dnsPacket.setQuery(true);
		dnsPacket.setRecursionAvailable(true);
		dnsPacket.setRecursionDesired(true);
		for (int i = 0; i < dnsPacket.getAdditional().size(); i++){
			dnsPacket.removeAdditional(dnsPacket.getAdditional().get(i));
		}
		for (int i = 0; i < dnsPacket.getAuthorities().size(); i++){
			dnsPacket.removeAuthority(dnsPacket.getAuthorities().get(i));
		}
	}

	private static void addAnsToReply(DNS dnsPacket, DNS toSendToClient){
		int addtionalSize = dnsPacket.getAdditional().size();
		int authoritySize = dnsPacket.getAuthorities().size();
		for (int i = 0; i < addtionalSize; i++){
			toSendToClient.addAdditional(dnsPacket.getAdditional().get(i));
		}
		for (int i = 0; i < authoritySize; i++){
			toSendToClient.addAuthority((dnsPacket.getAuthorities().get(i)));
		}
	}

	private static void sendDNSReply(DNS dnsPacket, DatagramPacket toSend) throws IOException{
		if(dnsPacket.getQuestions().get(0).getType() == DNS.TYPE_A){
			System.out.println("********** Checking if in EC2 regions ************");
			checkIfInEC2(dnsPacket);
			System.out.println("************** Checking done *********************");
		}
		DatagramPacket ans = new DatagramPacket(dnsPacket.serialize(), 0, dnsPacket.getLength(), toSend.getSocketAddress());
		serverSocket.send(ans);
		System.out.println("Sent answer to client");
	}

	/** Map(ip/subnetLength -> geoLocation) */
	private static Map<String, String> loadEC2Table(String file) {
		Map<String, String> ec2Map = new HashMap<String, String>();
		BufferedReader br = null;
		String line;
		String cvsDelimiter = ",";
		try {
			br = new BufferedReader(new FileReader(file));
			while ((line = br.readLine()) != null) {
				String[] entry = line.split(cvsDelimiter);
				String ip = entry[0];
				String location = entry[1];
				ec2Map.put(ip, location);
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return ec2Map;
	}

	private static void checkIfInEC2(DNS dnsPacket){
		if(dnsPacket.getAdditional().size() > 0){
			for (int i = 0; i < dnsPacket.getAnswers().size(); i++) {
				if (dnsPacket.getAnswers().get(i).getType() != DNS.TYPE_A){
					continue;
				}
				DNSRdataAddress addressString = (DNSRdataAddress) dnsPacket.getAnswers().get(i).getData();
				String addressInt = addressString.getAddress().toString();
				String ip = addressInt.substring(addressInt.indexOf("/") + 1); // e.g. 73.252.22.1

				for (String entry : ec2Table.keySet()) {
					long ipInt = parseIp(ip);
					long subnet = parseIp(entry.substring(0, entry.indexOf("/")));
					int subnetLength = Integer.parseInt(entry.substring(entry.indexOf("/") + 1));
					long subnetBits = 0xffffffff - ((1 << (32 - subnetLength)) - 1);
					if ((subnetBits & ipInt) == (subnetBits & subnet)) {
						System.out.println("This IP is in EC2!");
						String location = ec2Table.get(entry);
						DNSRdataString txt = new DNSRdataString(location + "-" + ip);
						DNSResourceRecord record = new DNSResourceRecord();
						record.setType(DNS.TYPE_TXT);
						record.setName(addressString.toString());
						record.setData(txt);
						dnsPacket.addAnswer(record);
					} else {
						System.out.println("This IP is NOT in EC2!");
					}
				}
			}
		}
	}

	private static long parseIp(String address) {
		long result = 0;

		// iterate over each octet
		for(String part : address.split(Pattern.quote("."))) {
			// shift the previously parsed bits over by 1 byte
			result = result << 8;
			// set the low order bits to the current octet
			result |= Integer.parseInt(part);
		}
		return result;
	}
}
