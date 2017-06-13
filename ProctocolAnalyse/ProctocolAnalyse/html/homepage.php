<html>
	<head>
		<mate charset="utf-8">
		<title>HOMEPAGE</title>
	</head>
	<body>
		<h1><center>welcome to Protocol Identification system</center></h1>
		<?php
			echo "Verbose Mode <input type='button' name='submit' value='search' onclick=\"location.href='verbose.php'\"></br>";
			echo "Simple Mode <input type='button' name='submit' value='search' onclick=\"location.href='simple.php'\"></br>";
		?>
		<h2>Condition Select</h2>
		<hr>
		<form name="form1" method="POST" action="condition.php">
			<table border="1" width="600">
				<tr><td>please select:
					<select size="1" name="options">
					<option value="PriIP">Saddr</option>
					<option value="ExIP">Daddr</option>
					<option value="PriPort">Sport</option>
					<option value="ExPort">Dport</option>
					<option value="App">App</option>
					<option value="Time">Time</option>
					</select>
				</td></tr>
				<tr><td>please enter:<input type="text" name="para"></td></tr>
				<tr><td>select by time:</td></tr>
				<tr><td>begin time:
				<input type="text" name="BeginTime"></td></tr>
				<tr><td>end time:
				<input type="text" name="EndTime"></td></tr>
				<tr><td align="center"><input type="submit" value="submit"></td></tr>
			</table>
		</form>
	</body>
</html>
