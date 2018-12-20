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
	private static String serverName;
	private static Map<String, String> ec2Table;
	private static DatagramSocket serverSocket;
	private final static int CLIENT_DNS_PORT = 8053;
	private final static int QUERY_DNS_PORT = 53;
	private final static int MAX_PACKET_SIZE = 1024;
	private final static int MAX_TIME_OUT = 2000;

	public static void main(String[] args) {
		System.out.println("Hello, DNS!");


		if (args.length != 4) {
			System.out.println("Invalid Arguments!");
			return;
		}
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-r")) {
				serverName = args[++i];
			} else if (args[i].equals("-e")) {
				ec2Table = loadEC2Table(args[++i]);
			} else {
				System.out.println("Invalid Arguments!");
				return;
			}
		}
		// open a socket
		startDnsServer();
	}

	private static void startDnsServer(){

		byte[] buffer = new byte[MAX_PACKET_SIZE];
		DNS dnsPacket;
		DNSQuestion question;

		try {
			serverSocket = new DatagramSocket(CLIENT_DNS_PORT);
			System.out.println("Socket initialization succeeded, listening...(root server is " + serverName + ")");
			while(true){
				DatagramPacket dnsReceived = new DatagramPacket(buffer, buffer.length);
				serverSocket.receive(dnsReceived);
				System.out.println("--------------Handling DNS query-----------------");
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
				handleDnsQuery(dnsPacket, dnsReceived);
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

	private static void handleDnsQuery(DNS dnsPacket, DatagramPacket dnsReceived) throws IOException {
		// Check NS then reply to client, if in EC2, add a TXT record to reply
		byte[] buffer = new byte[MAX_PACKET_SIZE];
		DatagramPacket query;
		List<DNSQuestion> questions = dnsPacket.getQuestions();
		InetAddress serverAddress = InetAddress.getByName(serverName);
		DatagramSocket socket = new DatagramSocket(QUERY_DNS_PORT);
		DNS toSendToClient = dnsPacket;
		boolean done = false;

		while(!done) {
			System.out.println("Sending query for: " + dnsPacket.getId());
			for (DNSQuestion q : dnsPacket.getQuestions()) {
				System.out.println(q.toString());
			}
			query = new DatagramPacket(dnsPacket.serialize(), dnsPacket.getLength(), serverAddress, QUERY_DNS_PORT);
			// This socket is used to send query to server
			socket.send(query);
			System.out.println("Sent query to server " + serverAddress.toString() + ". asking for " + dnsPacket.getQuestions().get(0).toString());
			socket.setSoTimeout(MAX_TIME_OUT);
			try {
				socket.receive(new DatagramPacket(buffer, buffer.length));
			} catch (SocketTimeoutException s) {
				System.out.println("Didn't receive answer from server " + serverAddress.toString());
				System.out.println("-----------------Query failed--------------------");
				break;
			}
			System.out.println("Received back from server: " + serverAddress.toString());
			// dnsPacket is updated every loop
			dnsPacket = DNS.deserialize(buffer, buffer.length);
			List<DNSResourceRecord> rootAnswers = dnsPacket.getAnswers();
			List<DNSResourceRecord> rootAuthorities = dnsPacket.getAuthorities();
			List<DNSResourceRecord> rootAdditional = dnsPacket.getAdditional();
			if(!dnsPacket.isRecursionDesired()){
				// Send back to client
				sendDNSReply(dnsPacket, dnsReceived);
				done = true;
			} else {
				if (rootAnswers.isEmpty()) {
					// if original query was NS, then done.
					if (questions.get(0).getType() == DNS.TYPE_NS) {
						toSendToClient.setAnswers(dnsPacket.getAdditional());
						sendDNSReply(dnsPacket, dnsReceived);
						done = true;
					}
					// look for ip of authority in additional section
					for (DNSResourceRecord auth : rootAuthorities) {
						boolean serverUpdated = false;
						System.out.println("This auth is " + auth.toString());
						System.out.println("All additionls are: ");
						for (DNSResourceRecord additional : rootAdditional) {
							System.out.println(additional.toString());
						}
						if (auth.getType() != DNS.TYPE_NS) {
							continue;
						}
						DNSRdataName nsName = (DNSRdataName) auth.getData();
						for (DNSResourceRecord additional : rootAdditional) {
							if (additional.getType() == DNS.TYPE_A
									&& nsName.getName().equals(additional.getName()))
							{
								System.out.println("This addtional matches: " + additional.toString());
								String addressName = additional.getName();
								serverAddress = InetAddress.getByName(addressName);
								System.out.println("Updated Server to query " + serverAddress.toString());
								serverUpdated = true;
								break;
							}
						}
						if (serverUpdated) break;
					}
					// Add additionals, authorities to reply
					toSendToClient.setAdditional(rootAdditional);
					toSendToClient.setAuthorities(rootAuthorities);

				} else { // Hold toSendToClient until get answers
					System.out.println("Got Answers from server!");
					boolean containTypeA = false;
					for (DNSResourceRecord ans : rootAnswers){
						if (ans.getType() == DNS.TYPE_A) {
							containTypeA = true;
							break;
						}
					}
					if(!containTypeA){
						for (DNSResourceRecord ans : rootAnswers){
							if (ans.getType() == DNS.TYPE_CNAME){
								DNSQuestion newQuestion = new DNSQuestion();
								newQuestion.setName(ans.getData().toString());
								newQuestion.setType(DNS.TYPE_A);
								newQuestion.setClass(DNS.CLASS_IN);
								dnsPacket.setQuestions(Collections.singletonList(newQuestion));
							}
						}
					} else {
						toSendToClient.setAnswers(rootAnswers);
						sendDNSReply(toSendToClient, dnsReceived);
						done = true;
					}
				}
			}
			prepareNewQuery(dnsPacket, questions);
		}
		socket.close();
	}

	private static void prepareNewQuery(DNS dnsPacket, List<DNSQuestion> questions){
		dnsPacket.setQuery(true);
		dnsPacket.setOpcode(DNS.OPCODE_STANDARD_QUERY);
		dnsPacket.setTruncated(false);
		dnsPacket.setRecursionAvailable(true);
		dnsPacket.setRecursionDesired(false);
		dnsPacket.setAuthenicated(false);
		dnsPacket.setQuestions(questions);
		dnsPacket.setAuthorities(new LinkedList<>());
		dnsPacket.setAdditional(new LinkedList<>());
	}

	private static void sendDNSReply(DNS dnsPacket, DatagramPacket dnsReceived) throws IOException{
		if(dnsPacket.getQuestions().get(0).getType() == DNS.TYPE_A){
			System.out.println("********** Checking if in EC2 regions ************");
			addEC2ToAns(dnsPacket);
			System.out.println("************** Checking done *********************");
		}
		DatagramPacket ans = new DatagramPacket(dnsPacket.serialize(), 0, dnsPacket.getLength(), dnsReceived.getSocketAddress());
		serverSocket.send(ans);
		System.out.println("Sent answer to client");
	}

	/** Map(ip/subnetLength -> geoLocation) */
	private static Map<String, String> loadEC2Table(String file) {
		System.out.println("Loading static EC2 table from " + file);
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

	private static void addEC2ToAns(DNS dnsPacket){
		for (int i = 0; i < dnsPacket.getAnswers().size(); i++) {
			if (dnsPacket.getAnswers().get(i).getType() != DNS.TYPE_A){
				System.out.println("Not an IPv4 address");
				continue;
			}
			DNSRdataAddress addressData = (DNSRdataAddress) dnsPacket.getAnswers().get(i).getData();
			String addressString = addressData.getAddress().toString();
			String ipStr = addressString.substring(addressString.indexOf("/") + 1); // e.g. 73.252.22.1
			System.out.println("Checking if address " + ipStr + " is in EC2");
			boolean found = false;
			for (String entry : ec2Table.keySet()) {
				long ip = parseIp(ipStr);
				long serverIP = parseIp(entry.substring(0, entry.indexOf("/")));
				int subnetLength = Integer.parseInt(entry.substring(entry.indexOf("/") + 1));
				long subnetBits = 0xffffffff - ((1 << (32 - subnetLength)) - 1);
				if ((subnetBits & ip) == (subnetBits & serverIP)) {
					found = true;
					String location = ec2Table.get(entry);
					DNSRdataString txt = new DNSRdataString(location + "-" + ip);
					DNSResourceRecord record = new DNSResourceRecord();
					record.setType(DNS.TYPE_TXT);
					record.setName(addressData.toString());
					record.setData(txt);
					dnsPacket.addAnswer(record);
				}
			}
			if (found) System.out.println("This ip is found in EC2");
			else System.out.println("This ip is NOT found in EC2");
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
