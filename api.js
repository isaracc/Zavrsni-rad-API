//tokens.createIndex({ expireAt: 1 }, { expireAfterSeconds: 60*60*2 });

const express = require("express");
const cors = require("cors");
require("dotenv").config();
const crypto = require("crypto");
const app = express();
const { MongoClient } = require("mongodb");

const client = new MongoClient(process.env.DB_URL);
client.connect();

const port = 3001;
const algorithm = "aes-256-cbc";
const initVector = process.env.INIT_VECTOR;
const securitykey = process.env.SECURITY_KEY;

function encryptData(data) {
	const cipher = crypto.createCipheriv(algorithm, securitykey, initVector);
	let encryptedData = cipher.update(data, "utf-8", "hex");
	encryptedData += cipher.final("hex");
	return encryptedData;
}

function decryptData(data) {
	const decipher = crypto.createDecipheriv(algorithm, securitykey, initVector);
	let decryptedData = decipher.update(data, "hex", "utf-8");
	decryptedData += decipher.final("utf-8");
	return decryptedData;
}

app.use(
	cors({
		origin: [
			"https://zavrsni-rad-sarac.herokuapp.com",
			"http://localhost:3000",
		],
	}),
	express.urlencoded({
		extended: true,
	}),
	express.json()
);

const db = client.db("INADB");
const users = db.collection("users");
const tokens = db.collection("tokens");
const services = db.collection("services");
const computers = db.collection("computers");
const logs = db.collection("logs");

async function validateToken(token = "") {
	let user;
	let exist = false;

	const userID = (
		await tokens.findOne({ token }, { projection: { _id: 0, user: 1 } })
	)?.user;

	const newUser =
		(await users.countDocuments({
			_id: userID,
			status: "Neaktivan",
		})) === 1;

	const activeAccount =
		(await users.countDocuments({
			_id: userID,
			status: "Aktivan",
		})) === 1;

	if (userID !== null) {
		user = await users.findOne(
			{ _id: userID },
			{
				projection: {
					role: 1,
					lastName: 1,
					name: 1,
					email: 1,
					status: 1,
				},
			}
		);
		exist = true;
	}

	return {
		exist: exist && (activeAccount || newUser),
		...user,
		newUser,
	};
}

async function createLog({ content = "", user = "" }) {
	return (await logs.insertOne({ content, user, time: new Date() }))
		.acknowledged;
}

const replaceText = [
	{ text: "computerName", alt: "Naziv računala" },
	{ text: "SN", alt: "Serijski broj" },
	{ text: "warranty", alt: "Garancija" },
	{ text: "specs", alt: "Specifikacije" },
	{ text: "storage", alt: "Prostor za skladištenje" },
	{ text: "name", alt: "Ime" },
	{ text: "lastName", alt: "Prezime" },
	{ text: "email", alt: "Email" },
	{ text: "role", alt: "Vrsta ovlasti" },
	{ text: "computers", alt: "Zadužena računala" },
];

function findChanges(obj1, obj2) {
	const keys1 = Object.keys(obj1);
	const keys2 = Object.keys(obj2);
	const allKeys = [...new Set([...keys1, ...keys2])];
	let diff = [];
	for (const key of allKeys) {
		if (
			obj2[key] &&
			key !== "created" &&
			JSON.stringify(obj1[key]) !== JSON.stringify(obj2[key])
		) {
			let text = replaceText.find((el) => el.text === key)?.alt;
			diff.push(`${text !== undefined ? text : key}`);
		}
	}
	return diff;
}

app.all("/", async (req, res) => {
	res.send("API je aktivan.");
});

app.post("/checkToken", async (req, res) => {
	let { exist, role, lastName, name, newUser } = await validateToken(
		req.body.token
	);
	if (!exist) {
		res.sendStatus(401);
		return;
	}
	res.send({
		role,
		name,
		lastName,
		newUser,
	});
});

app.post("/login", async (req, res) => {
	const { password, email } = req.body;
	let token = "";
	let user = await users.findOne(
		{
			$or: [
				{
					$and: [
						{
							$expr: {
								$eq: [{ $toLower: "$email" }, { $toLower: email }],
							},
						},
						{ password: encryptData(password) },
						{ status: "Aktivan" },
					],
				},
				{
					$and: [
						{
							$expr: {
								$eq: [{ $toLower: "$email" }, { $toLower: email }],
							},
						},
						{ password: "" },
						{ status: "Neaktivan" },
					],
				},
			],
		},
		{ projection: { role: 1, name: 1, lastName: 1, status: 1 } }
	);
	if (user !== null) {
		const tokens = db.collection("tokens");
		token = encryptData(`${new Date()}|${email}`);
		await tokens.deleteMany({ user: user._id });
		await tokens.insertOne({
			token,
			user: user._id,
			CreatedAt: new Date(),
		});
		createLog({
			content: `Korisnik ${user._id} se uspješno prijavio.`,
			user: user._id,
		});
		res.send({
			token,
			role: user?.role,
			name: user?.name,
			lastName: user?.lastName,
			newUser: user?.status === "Neaktivan",
		});
	} else res.sendStatus(404);
});

app.post("/logout", async (req, res) => {
	const { token } = req.body;
	const { user } = await tokens.findOne({ token }, { projection: { user: 1 } });
	let response = await tokens.deleteOne({ token });
	if (response.deletedCount > 0)
		createLog({ content: `Korisnik ${user} se uspješno odjavio.`, user });
	res.send(response.deletedCount > 0);
});

app.post("/dashboard/home", async (req, res) => {
	if (!(await validateToken(req.body.token)).exist) {
		res.sendStatus(401);
		return;
	}
	const year = new Date().getFullYear();
	const chartData = (
		await services
			.aggregate([
				{
					$match: {
						created: {
							$gte: new Date(`${year}-01-01`),
							$lt: new Date(`${year + 1}-01-01`),
						},
					},
				},
				{
					$group: {
						_id: { $month: "$created" },
						services: { $sum: 1 },
					},
				},
			])
			.sort({
				_id: 1,
			})
			.project({ _id: 0 })
			.toArray()
	).map((el) => el.services);
	res.send({
		users: await users.countDocuments({ role: "Korisnik" }),
		repairer: await users.countDocuments({ role: "Serviser" }),
		services: {
			active: await services.countDocuments({ status: "Aktivan" }),
			idle: await services.countDocuments({ status: "Na čekanju" }),
			finished: await services.countDocuments({ status: "Izvršeno" }),
			all: await services.countDocuments(),
		},
		chart: Array(12)
			.fill()
			.map((_, i) => chartData[i] || 0),
	});
});

app.post("/dashboard/computers", async (req, res) => {
	const { filters, skip = 0, limit = 20 } = req.body;
	const { exist, role, _id } = await validateToken(req.body.token);

	if (!exist) {
		res.sendStatus(401);
		return;
	}

	let options = {};

	if (role === "Korisnik")
		options._id = {
			$in: (await users.findOne({ _id }, { projection: { computers: 1 } }))
				.computers,
		};

	if (filters?.status !== undefined && filters.status !== 2)
		options.status = filters.status === 0 ? "Ispravan" : "Na servisu";

	if (filters?.search !== undefined && filters.search !== "") {
		options.$or = [
			{ SN: new RegExp(filters.search, "i") },
			{ _id: new RegExp(filters.search, "i") },
			{ computerName: new RegExp(filters.search, "i") },
		];
	}

	let data = await computers
		.find(options)
		.sort({ created: -1 })
		.skip(skip)
		.limit(limit)
		.toArray();

	res.send(data);
});

app.post("/dashboard/logs", async (req, res) => {
	const { filter, skip = 0, limit = 20 } = req.body;
	if (!(await validateToken(req.body.token)).exist) {
		res.sendStatus(401);
		return;
	}
	let options = {};
	if (filter !== undefined && filter !== "") {
		options.$or = [
			{ user: new RegExp(filter, "i") },
			{ content: new RegExp(filter, "i") },
		];
	}

	let data = (
		await logs
			.find(options, { projection: { _id: 0 } })
			.sort({ _id: -1 })
			.skip(skip)
			.limit(limit)
			.toArray()
	).map((el) => {
		return {
			...el,
			time: new Date(el.time).toLocaleString("hr-HR", {
				year: "numeric",
				month: "numeric",
				day: "numeric",
				hour: "numeric",
				minute: "numeric",
				second: "numeric",
			}),
		};
	});

	res.send(data);
});

app.post("/dashboard/users", async (req, res) => {
	const { filters, skip = 0, limit = 20 } = req.body;
	if (!(await validateToken(req.body.token)).exist) {
		res.sendStatus(401);
		return;
	}

	let options = {};

	if (filters?.role !== undefined && filters.role !== 3) {
		options.role =
			filters.role === 0
				? "Korisnik"
				: filters.role === 1
				? "Administrator"
				: filters.role === 2
				? "Serviser"
				: "";
	}

	if (filters?.status !== undefined && filters.status !== 2) {
		options.status =
			filters.status === 0
				? "Aktivan"
				: filters.status === 1
				? "Neaktivan"
				: "";
	}

	if (filters?.search !== undefined && filters.search !== "") {
		const reg = new RegExp(filters.search, "i");
		options.$or = [
			{ name: reg },
			{ _id: reg },
			{ lastName: reg },
			{ email: reg },
		];
	}

	let usersData = await users
		.find(options, {
			projection: {
				password: 0,
			},
		})
		.sort({ created: -1 })
		.skip(skip)
		.limit(limit)
		.toArray();

	for (let i = 0; i < usersData.length; i++) {
		usersData[i].computers = await computers
			.find({ _id: { $in: usersData[i]?.computers } })
			.toArray();
	}
	res.send(usersData);
});

app.post("/dashboard/services", async (req, res) => {
	const { filters, skip = 0, limit = 20 } = req.body;

	const { exist, role, _id } = await validateToken(req.body.token);
	if (!exist) {
		res.sendStatus(401);
		return;
	}
	let options = {};

	if (role === "Korisnik") options.user = _id;

	if (filters?.active !== undefined && filters.active !== 4) {
		options.status =
			filters.active === 0
				? "Na čekanju"
				: filters.active === 1
				? "Aktivan"
				: filters.active === 2
				? "Izvršen"
				: filters.active === 3
				? "Odbijen"
				: "";
	}

	if (filters?.search !== undefined && filters.search !== "") {
		const reg = new RegExp(filters.search, "i");
		options.$or = [
			{ user: reg },
			{ _id: reg },
			{ computer: reg },
			{ description: reg },
		];
	}

	let serviceData = await services
		.aggregate(
			[
				{ $match: options },
				{
					$addFields: {
						sortField1: {
							$cond: [
								{ $eq: ["$status", "Na čekanju"] },
								1,
								{
									$cond: [
										{ $eq: ["$status", "Aktivan"] },
										2,
										{
											$cond: [{ $eq: ["$status", "Izvršeno"] }, 3, 4],
										},
									],
								},
							],
						},
					},
				},
				{ $sort: { sortField1: 1, urgently: -1 } },
			],
			options
		)
		.skip(skip)
		.limit(limit)
		.toArray();

	for (let i = 0; i < serviceData.length; i++) {
		delete serviceData[i].sortField1;
		serviceData[i].urgently = serviceData[i].urgently ? "da" : "ne";
		serviceData[i].user = (
			await users
				.find({ _id: serviceData[i].user })
				.sort({ created: -1 })
				.project({ _id: 1, name: 1, lastName: 1, email: 1 })
				.toArray()
		)[0];
		if (serviceData[i]?.servicer !== undefined) {
			let servicerData = await users.findOne(
				{ _id: serviceData[i].servicer },
				{ projection: { _id: 0, name: 1, lastName: 1 } }
			);
			serviceData[
				i
			].servicer = `${servicerData.name} ${servicerData.lastName} (${serviceData[i].servicer})`;
		}
		if (serviceData[i].computer?._id === undefined)
			serviceData[i].computer = (
				await computers
					.find({ _id: serviceData[i].computer })
					.sort({ created: -1 })
					.project({ _id: 1, SN: 1, computerName: 1, warranty: 1 })
					.toArray()
			)[0];
	}
	res.send(serviceData);
});

app.post("/search/computers", async (req, res) => {
	const { filter, selected = [], computerID = "" } = req.body;
	if (!(await validateToken(req.body.token)).exist) {
		res.sendStatus(401);
		return;
	}
	let data = [];

	let ids = [];
	selected.forEach((el) => {
		ids.push(el._id);
	});
	let options = { _id: { $nin: ids } };
	if (filter !== undefined && filter !== "") {
		options.$or = [
			{ SN: new RegExp(filter, "i") },
			{ _id: new RegExp(filter, "i") },
			{ computerName: new RegExp(filter, "i") },
		];
	}
	if (computerID === "")
		data = await computers
			.find(options)
			.project({ _id: 1, SN: 1, computerName: 1, status: 1 })
			.sort({ created: -1 })
			.toArray();
	else data = await computers.findOne({ _id: computerID });

	res.send(data);
});

app.post("/search/user", async (req, res) => {
	const { filter, computersOnly, selectedComputer } = req.body;
	const { exist, _id } = await validateToken(req.body.token);
	if (!exist) {
		res.sendStatus(401);
		return;
	}
	let data = {};

	let options = {};
	if (filter !== undefined && filter !== "") {
		options.$or = [
			{ SN: new RegExp(filter, "i") },
			{ _id: new RegExp(filter, "i") },
			{ computerName: new RegExp(filter, "i") },
		];
	}

	let userData = (
		await users
			.find({ _id: _id })
			.project({ _id: 1, name: 1, lastName: 1, email: 1, computers: 1 })
			.sort({ created: -1 })
			.limit(1)
			.toArray()
	)[0];

	const computersData = await computers
		.find({
			_id: { $in: userData.computers, $ne: selectedComputer._id },
			status: { $ne: "Na servisu" },
			...options,
		})
		.project({ _id: 1, SN: 1, computerName: 1, status: 1 })
		.sort({ created: -1 })
		.toArray();
	if (computersOnly) data = computersData;
	else {
		delete userData.computers;
		data = userData;
	}
	res.send(data);
});

app.post("/createNew/PC", async (req, res) => {
	const { value } = req.body;
	const tokenData = await validateToken(req.body.token);
	if (!tokenData.exist || tokenData.role !== "Administrator") {
		res.sendStatus(401);
		return;
	}

	let success;

	let _id = await computers.findOne(
		{},
		{
			sort: { created: -1 },
		}
	);
	_id = _id?._id;
	if (typeof _id === "string") {
		_id = _id.slice(4);
		_id = parseInt(_id);
	}

	value.specs.storage.forEach((el, i) => {
		el.id = i;
	});

	_id = `#PC-${typeof _id !== "undefined" && !isNaN(_id) ? _id + 1 : 0}`;

	success = await computers.insertOne({
		...value,
		status: "Ispravan",
		created: new Date(),
		_id,
	});

	if (success?.acknowledged)
		createLog({
			content: `Korisnik ${tokenData._id} je kreirao računalo ${_id}`,
			user: tokenData._id,
		});
	res.send(success?.acknowledged);
});

app.post("/check/email", async (req, res) => {
	const { email } = req.body;
	const tokenData = await validateToken(req.body.token);
	if (!tokenData.exist || tokenData.role !== "Administrator") {
		res.sendStatus(401);
		return;
	}

	let userEmail = (
		await users.findOne(
			{
				email: {
					$regex: new RegExp("^" + email.slice(0, -7), "i"),
				},
			},
			{ projection: { email: 1, _id: 0 }, sort: { created: -1 } }
		)
	)?.email;
	if (userEmail === undefined) {
		res.send("");
		return;
	}
	userEmail = userEmail.slice(0, -7).split(email);
	if (userEmail[0] === "" && !isNaN(userEmail[1])) {
		res.send({ end: userEmail[1] === "" ? 1 : parseInt(userEmail[1]) + 1 });
	} else res.send({ end: "" });
});

app.post("/reset/user/password", async (req, res) => {
	const { _id } = req.body;
	const tokenData = await validateToken(req.body.token);
	if (!tokenData.exist || tokenData.role !== "Administrator") {
		res.sendStatus(401);
		return;
	}
	let success = await users.findOneAndUpdate(
		{ _id },
		{ $set: { activated: null, password: "", status: "Neaktivan" } }
	);
	if (success?.ok)
		createLog({
			content: `Korisnik ${tokenData._id} je resetirao lozinku korisnika ${_id}.`,
			user: tokenData._id,
		});
	res.send(success?.ok === 1);
});

app.post("/createNew/user", async (req, res) => {
	const { value } = req.body;
	const tokenData = await validateToken(req.body.token);
	if (!tokenData.exist || tokenData.role !== "Administrator") {
		res.sendStatus(401);
		return;
	}
	if (
		(await users.findOne({ email: value.email }, { projection: { _id: 1 } }))
			?._id !== undefined
	) {
		res.sendStatus(400);
		return;
	}

	let _id = await users.findOne(
		{},
		{
			sort: { created: -1 },
		}
	);
	_id = _id?._id;
	if (typeof _id === "string") {
		_id = _id.slice(6);
		_id = parseInt(_id);
	}
	_id = `#USER-${typeof _id !== "undefined" && !isNaN(_id) ? _id + 1 : 0}`;
	let success = await users.insertOne({
		...value,
		status: "Neaktivan",
		password: "",
		created: new Date(),
		_id,
	});

	if (success?.acknowledged)
		createLog({
			content: `Korisnik ${tokenData._id} je kreirao korisnika ${_id}`,
			user: tokenData._id,
		});

	res.send(success?.acknowledged);
});

app.post("/createNew/service", async (req, res) => {
	const { value } = req.body;
	const tokenData = await validateToken(req.body.token);
	if (!tokenData.exist) {
		res.sendStatus(401);
		return;
	}
	let _id = await services.findOne(
		{},
		{
			sort: { created: -1 },
		}
	);
	_id = _id?._id;
	if (typeof _id === "string") {
		_id = _id.slice(10);
		_id = parseInt(_id);
	}

	let success = (
		await services.insertOne({
			...value,
			status: "Na čekanju",
			created: new Date(),
			_id: `#SERVICES-${
				typeof _id !== "undefined" && !isNaN(_id) ? _id + 1 : 0
			}`,
		})
	)?.acknowledged;

	if (success) {
		createLog({
			content: `Korisnik ${tokenData._id} je podnio zahtjev za servisiranje računala ${value.computer}`,
			user: tokenData._id,
		});
		await computers.updateOne(
			{ _id: value.computer },
			{ $set: { status: "Na servisu" } }
		);
	}

	res.send(success ? true : false);
});

app.post("/update/PC", async (req, res) => {
	const { computer } = req.body;
	const tokenData = await validateToken(req.body.token);
	if (
		!tokenData.exist ||
		(tokenData.role !== "Administrator" && tokenData.role !== "Serviser")
	) {
		res.sendStatus(401);
		return;
	}
	if (computer?.specs?.lastID) delete computer.specs.lastID;
	let obj = await computers.findOne({ _id: computer._id });
	const changes = findChanges(obj, computer);
	obj = { ...obj, ...computer };
	obj.specs.storage.forEach((el, i) => {
		el.id = i;
	});

	let success = (
		await computers.findOneAndUpdate({ _id: computer._id }, { $set: obj })
	)?.ok;

	if (success)
		createLog({
			content: `Korisnik ${tokenData._id} je ažurirao računalo ${
				computer._id
			}. Promjene su na poljima ${changes.toString()}`,
			user: tokenData._id,
		});

	res.send(success ? true : false);
});

app.post("/update/user", async (req, res) => {
	const { user } = req.body;
	const tokenData = await validateToken(req.body.token);
	if (!tokenData.exist || tokenData.role !== "Administrator") {
		res.sendStatus(401);
		return;
	}

	if (
		user.oldEmail &&
		(
			await users.findOne(
				{ email: user.oldEmail + "@ina.hr" },
				{ projection: { _id: 1 } }
			)
		)?._id !== undefined
	) {
		res.sendStatus(400);
		return;
	}

	let obj = await users.findOne({ _id: user._id });
	const changes = findChanges(obj, user);
	obj = { ...obj, ...user };
	let success = (await users.findOneAndUpdate({ _id: user._id }, { $set: obj }))
		?.ok;
	if (success)
		createLog({
			content: `Korisnik ${tokenData._id} je ažurirao korisnika ${
				user._id
			}. Promjene su na poljima ${changes.toString()}`,
			user: tokenData._id,
		});
	res.send(success ? true : false);
});

app.post("/update/user/password", async (req, res) => {
	const { password, name, lastName } = req.body;
	const { _id, exist } = await validateToken(req.body.token);
	if (!exist) {
		res.sendStatus(401);
		return;
	}

	let obj = {
		activated: new Date(),
		password: encryptData(password),
		status: "Aktivan",
	};
	if (name !== undefined) obj.name = name;
	if (lastName !== undefined) obj.name = lastName;

	let success = (
		await users.findOneAndUpdate(
			{ _id: _id },
			{
				$set: obj,
			}
		)
	)?.ok;

	if (success)
		createLog({
			content: `Korisnik ${_id} je aktivirao svoj korisnički račun.`,
			user: _id,
		});
	res.send(success ? true : false);
});

app.post("/update/service", async (req, res) => {
	const { service } = req.body;
	const tokenData = await validateToken(req.body.token);
	if (!tokenData.exist || tokenData.role !== "Serviser") {
		res.sendStatus(401);
		return;
	}
	let computerID = (await services.findOne({ _id: service._id })).computer;
	let obj = {};

	obj.status =
		service.accepted === 1
			? "Aktivan"
			: service.accepted === 0
			? "Odbijen"
			: "Izvršeno";

	if (service.accepted === 1 || service.accepted === 0) {
		obj.processed = new Date();
		obj.servicer = tokenData._id;
	} else obj.finished = new Date();

	if (obj.status === "Izvršeno")
		obj.computer = (
			await computers
				.find({ _id: computerID }, { projection: { status: 0, created: 0 } })
				.toArray()
		)[0];
	let success = (
		await services.findOneAndUpdate(
			{ _id: service._id },
			{
				$set: obj,
			}
		)
	)?.ok;
	console.log(service, computerID);
	if (service.accepted === 0 || service.accepted === 3)
		await computers.findOneAndUpdate(
			{ _id: computerID },
			{ $set: { status: "Ispravan" } }
		);
	if (success)
		createLog({
			content: `Korisnik ${tokenData._id} je ažurirao servis ${service._id} vezan za računalo ${computerID}.`,
			user: tokenData._id,
		});

	res.send(success ? true : false);
});

app.post("/delete/user", async (req, res) => {
	const { _id } = req.body;
	const tokenData = await validateToken(req.body.token);
	if (!tokenData.exist || tokenData.role !== "Administrator") {
		res.sendStatus(401);
		return;
	}
	let success = (await users.deleteOne({ _id: _id }))?.acknowledged;

	if (success)
		createLog({
			content: `Korisnik ${tokenData._id} je uklonio korisnika ${_id}`,
			user: tokenData._id,
		});
	res.send(success ? true : false);
});

app.post("/delete/PC", async (req, res) => {
	const { _id } = req.body;
	const tokenData = await validateToken(req.body.token);
	if (!tokenData.exist || tokenData.role !== "Administrator") {
		res.sendStatus(401);
		return;
	}
	let success = (await computers.deleteOne({ _id: _id }))?.acknowledged;
	if (success)
		createLog({
			content: `Korisnik ${tokenData._id} je uklonio računalo ${_id}`,
			user: tokenData._id,
		});
	res.send(success ? true : false);
});

app.listen(process.env.PORT || port, () => {
	console.log(`API je uspješno pokrenut na portu ${port}.`);
});
