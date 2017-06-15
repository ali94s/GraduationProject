
<?php
	$conn=@mysqli_connect('localhost','root','root','mydatabase');
	if(mysqli_connect_errno($conn))
		echo 'failed to connect to MYSQL:'.mysqli_connect_errno();
	//echo "welcome";
	$para=$_POST["para"];
	$para2=$_POST["options"];
	if($para2=="Time")
	{
		$begin=strtotime($_POST["BeginTime"]);
		$end=strtotime($_POST["EndTime"]);
		$query="select * from FlowAnalyse where BeginTime>=$begin and EndTime<=$end";
		//echo $query;
	}
	else
	{
		$query="select * from FlowAnalyse where $para2='$para'";
		//echo $query;
	}
	$result=mysqli_query($conn,$query);
	echo "查询结果:";
	echo "<table border=1>";
	echo "<tr><td>源地址</td><td>目的地址</td><td>源端口</td><td>目的端口</td><td>传输层协议</td><td>应用层协议</td><td>开始时间</td><td>结束时间</td><td>流量</td><td>IP数据包</td></tr>";
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
