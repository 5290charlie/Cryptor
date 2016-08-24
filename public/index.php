<!DOCTYPE HTML>
<html>
	<head>
		<title>Cryptor</title>
	</head>
	<body>
		<h1>Encrypt File</h1>

		<form action="download.php" method="post" enctype="multipart/form-data">
			<input type="hidden" name="do" value="encrypt" />
			<label for="file">File</label>
			<input type="file" name="file" id="file" />
			<br />
			<label for="key">Key</label>
			<input type="password" name="key" id="key" />
			<br />
			<label for="confirm">Confirm</label>
			<input type="password" name="confirm" id="confirm" />
			<br />
			<label for="saveas">Save As</label>
			<input type="text" name="saveas" id="saveas" />
			(Default = encrypted-timestamp-originalfilename)
			<br />
			<input type="submit" name="submit" value="Encrypt" />
		</form>

		<hr>

		<h1>Decrypt File</h1>
		
		<form action="download.php" method="post" enctype="multipart/form-data">
			<input type="hidden" name="do" value="decrypt" />
			<label for="file">File</label>
			<input type="file" name="file" id="file" />
			<br />
			<label for="key">Key</label>
			<input type="password" name="key" id="key" />
			<br />
			<label for="saveas">Save As</label>
			<input type="text" name="saveas" id="saveas" />
			(Default = decrypted-timestamp-originalfilename)
			<br />
			<input type="submit" name="submit" value="Decrypt" />
		</form>

	</body>
</html>
