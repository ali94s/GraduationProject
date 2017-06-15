<?php
	$conn=@mysqli_connect('localhost','root','root','mydatabase');
	if(mysqli_connect_errno($conn))
		echo 'failed to connect to MYSQL:'.mysqli_connect_errno();
	$query="select App,sum(Packets) Packets,sum(Flow) Flow from FlowAnalyse group by App";
	$result=mysqli_query($conn,$query);
	echo "查询结果:";
	echo "<table border=1>";
	echo "<tr><td>应用层协议</td><td>IP数据包</td><td>流量</td></tr>";
	while($row=mysqli_fetch_array($result))
	{
		echo "<tr>";
		echo "<td>".$row[App]."</td>";
		echo "<td>".$row[Packets]."</td>";
		echo "<td>".$row[Flow]."</td>";
		echo "</tr>";
	}	
	echo "</table>";
?>
