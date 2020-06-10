
public class ConnectionOverThread extends Thread{
	private PeerReceiverThread peerReceiverThread;
	private PeerSenderThread peerSenderThread;
	
	public ConnectionOverThread(PeerReceiverThread peerReceiverThread)
	{
		this.setPeerReceiverThread(peerReceiverThread);
	}
	
	public ConnectionOverThread(PeerSenderThread peerSenderThread)
	{
		this.peerSenderThread = peerSenderThread;
	}

	public void run()
	{	
		try {
			Thread.sleep(5);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public PeerReceiverThread getPeerReceiverThread() {
		return peerReceiverThread;
	}


	public void setPeerReceiverThread(PeerReceiverThread peerReceiverThread) {
		this.peerReceiverThread = peerReceiverThread;
	}
}
