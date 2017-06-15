<html>
	<head>
		<title>HOMEPAGE</title>
	</head>
		<h1><center>欢迎使用网络流量协议识别系统</center></h1>

		<?php
			echo "详细模式 <input type='button' name='submit' value='查看' onclick=\"location.href='verbose.php'\"></br>";
			echo "简易模式<input type='button' name='submit' value='查看' onclick=\"location.href='simple.php'\"></br>";
		?>
		<h2>条件选择</h2>
		<hr>
		<form name="form1" method="POST" action="condition.php">
			<table border="1" width="600">
				<tr><td>请选择查询条件:
					<select size="1" name="options">
					<option value="PriIP">源地址</option>
					<option value="ExIP">目的地址</option>
					<option value="PriPort">源端口</option>
					<option value="ExPort">目的端口</option>
					<option value="App">应用层协议</option>
					<option value="Time">起始时间</option>
					</select>
				</td></tr>
				<tr><td>请输入:<input type="text" name="para"></td></tr>
				<tr><td>通过起始时间查询:</td></tr>
				<tr><td>开始时间:
				<input type="text" name="BeginTime"></td></tr>
				<tr><td>结束时间:
				<input type="text" name="EndTime"></td></tr>
				<tr><td align="center"><input type="submit" value="提交"></td></tr>
			</table>
		</form>
	</body>
</html>
