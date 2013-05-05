### Explanations

1. First question is done via scapy. Values are normalized by the total number of the connections in the capture.
2. Second question is done via d3.js
3. I have imported a [library](https://github.com/cssaheel/dissectors) to parse IRC. After getting results, I have just written them into a file. Rest will depend on the application logic and I think it isn't interesting in terms of this test because what is left is only strings and extracting related parts in only string manipulation, not protocol dissecting.
4. Again, in terms of dissecting, I have used default IP, TCP layers of scapy. I have tried to check retransmission in the capture. Even if question is stated to encourage DNS packets, DNS packets are clean and suspicious activity are triggered a remote shell running on DNS port. 