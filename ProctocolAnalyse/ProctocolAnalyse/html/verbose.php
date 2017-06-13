<?php
	$conn=@mysqli_connect('localhost','root','root','mydatabase');
	if(mysqli_connect_errno($conn))
		echo 'failed to connect to MYSQL:'.mysqli_connect_errno();
	$query="select * from FlowAnalyse order by EndTime desc limit 0,20";
	$result=mysqli_query($conn,$query);
	echo "The query result is:";
	echo "<table border=1>";
	echo "<tr><td>PriIP</td><td>ExIP</td><td>PriPort</td><td>ExPort</td><td>Trans</td><td>App</td><td>BeginTime</td><td>EndTime</td><td>Flow</td><td>Packets</td></tr>";
	while($row=mysqli_fetch_array($result))
	{
		echo "<tr>";
		echo "<td>".$row[PriIP]."</td>";
		echo "<td>".$row[ExIP]."</td>";
		echo "<td>".$row[PriPort]."</td>";
		echo "<td>".$row[ExPort]."</td>";
		echo "<td>".$row[Trans]."</td>";
		echo "<td>".$row[App]."</td>";
		echo "<td>".date("Y-m-d H:i:s",$row[BeginTime])."</td>";
		echo "<td>".date("Y-m-d H:i:s",$row[EndTime])."</td>";
		echo "<td>".$row[Flow]."</td>";
		echo "<td>".$row[Packets]."</td>";
		echo "</tr>";
	}
	echo "</table>";
?>
