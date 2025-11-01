require("dotenv").config() // Läser in variabler filen .env där JWTSECRET finns lagrad
const jwt = require("jsonwebtoken") // Använder oss av JasonWebToken i Cookie-hanteringen
const sanitizeHTML = require("sanitize-html") // sanitize text-area för att förhindra injektion av skadlig kod
const bcrypt = require("bcrypt") // Hasha lösenord
const marked = require("marked") // Möjliggör så vald formatering kan tillåtas i text-are/innehåll i inläggen.
const cookieParser = require("cookie-parser") // Möjliggör access till cookie innehåll så vi t ex kan visa olika vyer ifall inloggad eller ej
const express = require("express") // Ramverk som användds
const db = require("better-sqlite3")("myGR8app.db") // Den SQL-db som används och namn på databasen
db.pragma("journal_mode = WAL") // Write Ahead Logging, gör så att skrivning/läsning tillåts samtidigt för bättre prestanda

// Skapande av databas startar här
const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `
        ).run()

    db.prepare(`
        CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body STRING NOT NULL,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users (id)
         )
        
        `).run()
})

createTables()

// Skapande av databas slutar här

const app = express()

app.set("view engine", "ejs") // Sätter app till att använda view engine "ejs"
app.use(express.urlencoded({extended: false})) // False säkerställer att express.urlencoded inte tillåter nästlade object eller arrays.
app.use(express.static(__dirname + '/public/')) // Använder style.css under mappen public
app.use(cookieParser())


// Egen Middleware (function) som körs vid varje inkommande http-request och innan routens
// egen "kod" alltså emellan anrop och exekvering (därav namnet) för att via "Next" sedan fortsätta med "nästa"
// kod/del av programmet.
app.use(function (req, res, next) {

    // Kör sanitize på inläggets innehåll samt att man här kan ange vilka html-taggar man vill tillåta som tillägget "marked" möjliggör.
    res.locals.filterUserHTML = function(content) {
        return sanitizeHTML(marked.parse(content), {
            allowedTags: ["p", "br", "ul", "li", "ol", "strong", "bold", "i", "em", "h1", "h2", "h3", "h4", "h5", "h6"],
            allowedAttributes: {}
        })
    }

    // Gör den lokala variabeln "errors" global så att homepage.ejs kan laddas utan felmeddelande "errors not defined..."
    res.locals.errors = []

    // Kollar om det finns en cookie och om den matchar den lokala JWTSECRET lagrad i filen .env.
    // Om det finns en giltig cookie så är en användare inloggad (och variabel req.user innehåller cookie-info). Om inte, så är ingen inloggad (req.user är då false).
    try {
        const decoded = jwt.verify(req.cookies.myGR8app, process.env.JWTSECRET)
        req.user = decoded
    } catch(err) {
        req.user = false

    }

    // gör det möjligt att använda cookie-valideringen via "req.user = decoded/False" utanför denna funktion.
    res.locals.user = req.user
  
    next()
})

// Om giltig cookie finns för current user visar nedan route "dashboard" och om inte visar den "homepage"
app.get("/", (req, res) => {
    if (req.user) {
        const postsStatement = db.prepare("SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC")
        const posts = postsStatement.all(req.user.userid)
        const otherPostStatement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE authorid != ? ORDER BY createdDate DESC")
        const otherPosts = otherPostStatement.all(req.user.userid)
        return res.render("dashboard", {posts, otherPosts})
    }
    res.render("homepage")
})

// Vid klick på login-knapp på homepage läses login-sidan in
app.get("/login", (req, res) => {
    res.render("login")
})

// Vid klick på logout-knapp tas cookie'n bort och omdirigering till homepage sker.
app.get("/logout", (req, res) => {
    res.clearCookie("myGR8app")
    res.redirect("/")
})

// vid klick på login-knapp valideras angivet användarnamn/lösenord, om allt är ok skapas en cookie med hjälp av JWTSECRET samt användarens unika ID
// och man dirigeras till dashboard vid lyckad inloggning.
app.post("/login", (req, res) => {
    let errors = []

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    if (req.body.username.trim() == "") errors = ["Ogiltigt användarnamn / lösenord"]
    if (req.body.password == "") errors = ["Ogiltigt användarnamn / lösenord"]

    if (errors.length) {
        return res.render("login", {errors})
    }

    // Hämtar info till variabel "userInQuestion" från tabell "users" som matchar det inmatade användarnamnet
    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)

    // Om ingen match hittades, så userInQuestion inte är satt, sätts felmeddelande till "errors"
    // och login-sidan läses in.
    if (!userInQuestion) {
        errors = ["Ogiltigt användarnamn / lösenord"]
        return res.render("login", {errors})
    }

    // variabel "matchOrNot" sätts till resultatet av bcrypts "compareSync" funktion som jämför inmatade löseordet 
    // med det sparade i databasen som hämtats till variabel userInQuestion. If sats hanterar sedan om det är match eller ej
    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if (!matchOrNot) {
        errors = ["Ogiltigt användarnamn / lösenord"]
        return res.render("login", {errors})
    }

    // Token skapas via JsonWebToken's sign funktion och lagras i variabel tokenValue
    // Giltighetstid sätts till 24 timmar och användar-ID och användarnamn samt den lokalt lagrade JWTSECRET-strängen som hämtas
    // ifrån filen .env. På så sätt säkras unika token men som kan "brytas ner" igen för att kolla ingående värden.
    const tokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, userid: userInQuestion.id, username: userInQuestion.username}, process.env.JWTSECRET)

    // En cookie skapas för användaren och tokenValue lagras i cookien. Giltighetstid på cookien sätts till 24 timmar. httpOnly säkerställer att
    // cookien endast kan läsas via http-protokollet. secure gör att det endast är via https men det gäller inte när vi kör lokalt, via localhost...
    // sameSite säkrar att det bara är den egna siten som kan läsa cookien.
    res.cookie("myGR8app", tokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect("/")

})


// Skapar konto
app.post("/register", (req, res) => {   
    const errors = []
// Nedan if-satser tömmer användarnamn/lösenord ifall det matats in annat än text-strängar
    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

// Tar bort eventuell tomrum innan/efter användarnamns-strängen
    req.body.username = req.body.username.trim()

// Kollar att användarnamn inte är tomt, längre än 3 tecken, kortare än 11 tecken samt att innehåll endast är bokstäver och siffror.
    if (!req.body.username) errors.push("Du måste ange ett användarnamn!")
    if (req.body.username && req.body.username.length < 3) errors.push("Användarnamn behöver vara längre än 3 tecken")
    if (req.body.username && req.body.username.length > 10) errors.push("Användarnamn kan inte vara längre än 10 tecken")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9åäöÅÄÖ]+$/)) errors.push("Användarnamn kan endast innehålla bokstäver och siffror.")

// Kollar att användarnamn inte redan finns i databasen
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const usernameCheck = usernameStatement.get(req.body.username)

    if (usernameCheck) errors.push("Användarnamn redan registrerat")

// Validering av löseordsinmatning
    if (!req.body.password) errors.push("Du måste ange ett lösenord!")
    if (req.body.password && req.body.password.length < 8) errors.push("Lösenord måste vara minst 8 tecken långt.")
    if (req.body.password && req.body.password.length > 40) errors.push("Lösenord kan inte vara längre än 40 tecken.")

    if (errors.length) {
        return res.render("homepage", {errors})
    }
    
//Hashar det inmatade löseordet
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

// Lagrar den nya användaren i databasen, users tabellen.
    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    const result = ourStatement.run(req.body.username, req.body.password)

// Hämtar det unika ID'et på sist adderade user (för att adderas till cookie i nästa steg)
    const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookupStatement.get(result.lastInsertRowid)

// Skapar token-värde  genom att kombinera olika data och även inkludera JWTSECRET från .env
    const tokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, userid: ourUser.id, username: ourUser.username}, process.env.JWTSECRET)

// Skapar en cookie som inkluderar det nyligen skapade token-värdet.
    res.cookie("myGR8app", tokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })

// Re-direkt till hemsidan som nu visar "dashboard" (användare inloggad)
    res.redirect("/")
})

// Återanvändbar funktion för att kolla om användaren är inloggad (req.user valideras till True)
function mustBeLoggedIn(req, res, next) {
    if (req.user) {
        return next()
    }
    return res.redirect("/")
}

// Endast inloggad användare kan komma till sidan "create-post"
app.get("/create-post", mustBeLoggedIn, (req, res) => {
    res.render("create-post")
})

// Funktion för att validera/sanitize inläggs-input (både titel samt innehåll), används både vid skapande- samt uppdatering av inlägg
function sharedPostValidation(req) {
    const errors = []

    // Om titel/innehåll är annat än text-sträng sätts de till "tomma"
    if (typeof req.body.title !== "string") req.body.title = ""
    if (typeof req.body.body !== "string") req.body.body = ""

    // funktionen sanitizeHTML körs på titel/innehåll som då också tillåter viss formatering/vissa html-taggar
    // som definierats i funktionen via "allowedTags" samt "allowedAttributes"
    req.body.title = sanitizeHTML(req.body.title.trim(), {allowedTags: [], allowedAttributes: {}})
    req.body.body = sanitizeHTML(req.body.body.trim(), {allowedTags: [], allowedAttributes: {}})

    // if satser som skickar meddelande ifall titel/innehåll är tomma.
    if (!req.body.title) errors.push("Du måste ange en titel")
    if (!req.body.body) errors.push("Du måste ge inlägget innehåll.")

    return errors
}

// Lagrar validerat/sanitized inlägg i databasen 
app.post("/create-post", mustBeLoggedIn, (req, res) => {
   const errors = sharedPostValidation(req)

   if (errors.length) {
    return res.render("create-post", {errors})
   }

// Lagrar inlägget i databasen
   const ourStatement = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)")
   const result = ourStatement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString())

// Hämtar unika id'et för senaste lagrade inlägget
   const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
   const realPost = getPostStatement.get(result.lastInsertRowid)

//Re-direct till senaste inläggets sida
   res.redirect(`/post/${realPost.id}`)

})

// Vid klick på Uppdatera inlägg-knappen för att komma till "edit-post"- sidan
app.get("/edit-post/:id", mustBeLoggedIn, (req, res) => {

// Försöker hämta  det specifika inlägget från databasen
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

     if (!post)
        return res.redirect("/")

    // Om annan än författare av inlägget, re-direct till homepage/dashboard
    if (post.authorid !== req.user.userid)
        return res.redirect("/")

        // Annars läs in sidan "edit-post" för rätt inlägg
    res.render("edit-post", { post })
})


// Vid klick på uppdatera-knappen för att uppdatera inlägget i databasen körs denna route
app.post("/edit-post/:id", mustBeLoggedIn, (req, res) => {
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

     if (!post)
        return res.redirect("/")

    // Om inte författaren till inlägget, redirect till homepage/dashboard
    if (post.authorid !== req.user.userid)
        return res.redirect("/")

    const errors = sharedPostValidation(req)

    // Om array "errors" innehåller något läses "edit-post" sidan in och felmeddelande presenteras.
    if (errors.length) {
        return res.render("edit-post", {errors})
    }

    // om allt OK så körs nedan och inlägget uppdateras
    const updateStatement = db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?")
    updateStatement.run(req.body.title, req.body.body, req.params.id)

    // Efter uppdatering av db record blir man dirigerad till det specifika inläggets sida (mallen "single-post")
    res.redirect(`/post/${req.params.id}`)

})

// För att radera ett inlägg
app.post("/delete-post/:id", mustBeLoggedIn, (req, res) => {

    // Försöker hämta inlägget från databasen
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

     if (!post)
        return res.redirect("/")

    // Om inte författaren till inlägget, redirect till homepage/dashboard
    if (post.authorid !== req.user.userid)
        return res.redirect("/")
    
    // Om allt OK skickas delete statement till databasen och det specifika inlägget raderas.
    const deleteStatement = db.prepare("DELETE FROM posts WHERE id = ?")
    deleteStatement.run(req.params.id)

    res.redirect("/")
})

// Vid klick på inläggs-länk öppnas sidan "single-post" om user är författaren av inlägget
app.get("/post/:id", (req, res) => {
    const statement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?")
    const post = statement.get(req.params.id)

    if (!post) {
        return res.redirect("/")
    }

    // kollar ifall författare av det specifika inlägget matchar med inloggad användare.
    // svara med att inlägget läses in via "single-post" mallen med tillhörnade information
    // ("post" samt om författare true/false via "isAuthor")
    const isAuthor = post.authorid === req.user.userid
    res.render("single-post", { post, isAuthor })
})

// Vid klick på länken "Radera konto!" läses sidan "delete-account" in som då också
// innehåller den inloggade användarens inlägg i en lista.
app.get("/delete-account", (req, res) => {

    const postsStatement = db.prepare("SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC")
    const posts = postsStatement.all(req.user.userid)

    res.render("delete-account", { posts })
})

// Vid klickande på knappen "Radera konto!" raderas inloggad användares inlägg, konto samt kakan tas bort.
// Svarar med redirect till "homepage"
app.post("/delete-account", (req, res) => {

    let errors = []

    const deleteAllStatement = db.prepare("DELETE FROM posts WHERE authorid = ?")
    const deleteAll = deleteAllStatement.run(req.user.userid)

    const deleteAccountStatement = db.prepare("DELETE FROM users WHERE id = ?")
    const deleteAccount = deleteAccountStatement.run(req.user.userid)

    res.clearCookie("myGR8app")

    return res.redirect("/")
})

// Sätter vilken port appen skall lyssna på
app.listen(3000)