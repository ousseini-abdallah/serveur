const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt'); // Pour le hachage des mots de passe
const nodemailer = require('nodemailer');
const path = require('path');
const { Server } = require('socket.io'); 
const http = require('http');
const server = http.createServer(); 
const io = new Server(server, {
  cors: {
    origin: '*', // Permet toutes les origines
    methods: ['GET', 'POST'], // Méthodes autorisées
  },
});
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() }); // Stocker le fichier en mémoire


// Initialisation Firebase Admin SDK
const serviceAccount = require('./configuration/serviceAccountKey.json'); // Clé privée Firebase
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });

// Initialisation d'Express
const app = express();

// Middleware
app.use(cors({ origin: '*' })); // Permet toutes les origines
app.use(bodyParser.json());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

async function hashPassword(password, saltRounds) {
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  } catch (error) {
    throw new Error('Erreur lors du hachage du mot de passe.');
  }
}
// Routes forum
//ap854p.use("/api/forum", forumRoutes);

// Route : Ajouter une offre d'emploi
app.post('/addJobOffer', async (req, res) => {
  try {
    const { title, company, description, location, salary, requirements, postedDate } = req.body;

    console.log(req.body); // Log le contenu reçu

    // Validation des données
    if (!title || !company) {
      return res.status(400).json({ error: 'Title and company are required.' });
    }

    console.log('Data received correctly:', req.body);

    // Nouvelle offre avec statut "pending"
    const newJobOffer = {
      title,
      company,
      description: description || 'Aucune description',
      location: location || 'Non spécifié',
      salary: salary || 'Non spécifié',
      requirements: requirements || [],
      postedDate: postedDate || new Date().toISOString(),
      status: 'pending', // Statut par défaut
      //postedBy: postedBy,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // Ajout dans Firestore
    const jobOfferRef = await db.collection('JobOffers').add(newJobOffer);

    res.status(201).json({ id: jobOfferRef.id, ...newJobOffer });
  } catch (error) {
    console.error('Erreur lors de l\'ajout de l\'offre :', error);
    res.status(500).json({ error: 'Erreur lors de l\'ajout de l\'offre' });
  }
});

//Route pour approuver/rejeter une offre
app.put('/updateJobOfferStatus/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body; // "approved" ou "rejected"

    // Validation du statut
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Statut invalide. Utilisez "approved" ou "rejected".' });
    }

    // Mise à jour du statut dans Firestore
    await db.collection('JobOffers').doc(id).update({ status });

    res.status(200).json({ message: 'Statut de l\'offre mis à jour avec succès' });
  } catch (error) {
    console.error('Erreur lors de la mise à jour du statut :', error);
    res.status(500).json({ error: 'Erreur lors de la mise à jour du statut' });
  }
});

//Route pour récupérer uniquement les offres en attente d'approbation
app.get('/getPendingJobOffers', async (req, res) => {
  try {
    // Récupérer les offres avec le statut "pending"
    const snapshot = await db.collection('JobOffers').where('status', '==', 'pending').get();

    const pendingOffers = [];
    snapshot.forEach((doc) => {
      pendingOffers.push({ id: doc.id, ...doc.data() });
    });

    res.status(200).json(pendingOffers);
  } catch (error) {
    console.error('Erreur lors de la récupération des offres en attente :', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des offres en attente' });
  }
});

//route pour récupérer uniquement les offres approuvées.
app.get('/getApprovedJobOffers', async (req, res) => {
  try {
    // Récupérer les offres avec le statut "approved"
    const snapshot = await db.collection('JobOffers').where('status', '==', 'approved').get();

    const approvedOffers = [];
    snapshot.forEach((doc) => {
      approvedOffers.push({ id: doc.id, ...doc.data() });
    });

    res.status(200).json(approvedOffers);
  } catch (error) {
    console.error('Erreur lors de la récupération des offres approuvées :', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des offres approuvées' });
  }
});

// Route : Lire toutes les offres d'emploi
app.get('/getJobOffers', async (req, res) => {
  try {
    const snapshot = await db.collection('JobOffers').get();
    const jobOffers = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    res.status(200).json(jobOffers);
  } catch (error) {
    console.error('Erreur lors de la récupération des offres :', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des offres' });
  }
});

app.put('/updateJobOffer/:id', async (req, res) => {
  const jobId = req.params.id;
  const updates = req.body;

  try {
    const jobRef = db.collection('JobOffers').doc(jobId);
    const doc = await jobRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Offre non trouvée.' });
    }

    await jobRef.update(updates);
    res.status(200).json({ success: true, message: 'Offre mise à jour avec succès.' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la mise à jour de l\'offre.', details: error.message });
  }
});

app.delete('/deleteJobOffer/:id', async (req, res) => {
  const jobId = req.params.id;

  try {
    const jobRef = db.collection('JobOffers').doc(jobId);
    const doc = await jobRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Offre non trouvée.' });
    }

    await jobRef.delete();
    res.status(200).json({ success: true, message: 'Offre supprimée avec succès.' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la suppression de l\'offre.', details: error.message });
  }
});


// Route pour enregistrer un utilisateur
app.post('/addAlumni', async (req, res) => {
  try {
    const data = req.body;
    console.log('Données reçues côté serveur:', data);
    // Vérifier si l'email existe déjà
    const usersRef = db.collection('Alumini');
    const querySnapshot = await usersRef.where('email', '==', data.email).get();
    if (!querySnapshot.empty) {
      return res.status(409).json({ message: 'Cet email est déjà utilisé.' });
    }
    // Générer un code de validation
    //const validationCode = generateValidationCode();
    // hacher le mot de passe
    if (!data.password) {
      return res.status(400).json({ message: 'Mot de passe requis.' });
    }
    const hashedPassword = await hashPassword(data.password, 10);

    // prépareration les données à enregistrer dans Firestore
    let alumniData = {
      nom: data.nom,
      prenom: data.prenom,
      email: data.email,
      //matricule: data.matricule,
      statut: data.statut || 'Étudiant' || 'Diplômé', // statut initialement 'Étudiant' ou 'Diplômé' fourni par l'utilisateur
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      photo: data.profileImageUrl || "",
      promotion: data.promotion || "",
      option: data.option || "",
      cycle: data.cycle || "",
    };

    // ajout les champs spécifiques pour les diplômés
    if (data.statut === 'Diplômé') {
      if (!data.grade || !data.anneeDiplomation || !data.travail) {
        return res.status(400).json({
          message: 'Les champs grade, année de diplomation et entreprise actuelle sont obligatoires pour les diplômés.',
        });
      }

      alumniData = {
        ...alumniData,
        grade: data.grade,
        anneeDiplomation: data.anneeDiplomation,
        currentCompany: data.currentCompany || "Non spécifié",
        travail: data.travail || "",
      };
    }

    console.log('Données préparées pour Firestore:', alumniData);
    // Enregistrer l'utilisateur dans Firestore
    const docRef = await db.collection('Alumini').add(alumniData);


    return res.status(201).json({
      message: 'Utilisateur enregistré avec succès. Un email de validation a été envoyé.',
      alumniId: docRef.id,
    });
  } catch (error) {
    console.error('Erreur lors de l\'enregistrement des données :', error);
    return res.status(500).json({ message: 'Erreur interne du serveur.', error: error.message });
  }
});


// Route pour vérifier le matricule
app.post('/checkMatricule', async (req, res) => {
  try {
    const { matricule } = req.body;

    // Vérifier si le matricule existe dans la collection 'matricules'
    const matriculeRef = db.collection('matricules');
    const query = await matriculeRef.where('matricule', '==', matricule).get();

    if (query.empty) {
      return res.status(400).json({ message: 'Matricule invalide.' });
    }

    // Si le matricule existe, renvoyer une réponse de succès
    return res.status(200).json({ message: 'Matricule valide.' });
  } catch (error) {
    console.error('Erreur lors de la vérification du matricule :', error);
    return res.status(500).json({ message: 'Erreur interne du serveur.', error: error.message });
  }
});


// Route pour authentifier un utilisateur
app.post('/auth', async (req, res) => {
  const { email, password } = req.body;

  // Afficher les données reçues
  console.log('Données reçues :', req.body);

  // Vérification des champs obligatoires
  if (!email || !password) {
    console.log('Email ou mot de passe manquant');
    return res.status(400).json({ message: 'Email et mot de passe sont requis.' });
  }

  try {
    // 1. Vérifier si l'utilisateur est un admin
    const adminRef = db.collection('admin');
    const adminSnapshot = await adminRef.where('email', '==', email).get();

    if (!adminSnapshot.empty) {
      const adminDoc = adminSnapshot.docs[0];
      const adminData = adminDoc.data();

      // Afficher les données de l'admin trouvé
      console.log('Admin trouvé :', adminData);

      // Vérifier le mot de passe (en clair pour l'admin)
      if (password !== adminData.password) {
        console.log('Mot de passe incorrect pour l\'admin');
        return res.status(401).json({ message: 'Mot de passe incorrect.' });
      }

      // Retourner la réponse pour l'admin
      const responseData = {
        message: 'Authentification réussie. Bienvenue, administrateur !',
        userId: adminDoc.id,
        role: 'admin',
      };

      console.log('Réponse envoyée pour l\'admin :', responseData);
      return res.status(200).json(responseData);
    }

    // 2. Si l'utilisateur n'est pas un admin, vérifier dans la collection Alumini
    const aluminiRef = db.collection('Alumini');
    const aluminiSnapshot = await aluminiRef.where('email', '==', email).get();

    if (aluminiSnapshot.empty) {
      console.log('Email non trouvé dans Alumini');
      return res.status(404).json({ message: 'L\'email n\'est pas enregistré.' });
    }

    const aluminiDoc = aluminiSnapshot.docs[0];
    const aluminiData = aluminiDoc.data();

    // Afficher les données de l'alumni trouvé
    console.log('Alumni trouvé :', aluminiData);

    // Vérifier le mot de passe (haché pour les alumni)
    const isPasswordValid = await bcrypt.compare(password, aluminiData.password);
    if (!isPasswordValid) {
      console.log('Mot de passe incorrect pour l\'alumni');
      return res.status(401).json({ message: 'Mot de passe incorrect.' });
    }

    // Retourner la réponse pour l'utilisateur
    const responseData = {
      message: 'Authentification réussie. Bienvenue, utilisateur !',
      userId: aluminiDoc.id,
      role: 'user',
      statut: aluminiData.statut, // Statut (Diplômé ou Étudiant)
    };

    console.log('Réponse envoyée pour l\'alumni :', responseData);
    return res.status(200).json(responseData);
  } catch (error) {
    console.error('Erreur lors de l\'authentification :', error);
    return res.status(500).json({ 
      message: 'Erreur interne du serveur.', 
      error: error.message 
    });
  }
});


// Récupérer tous les Alumni
app.get('/getAlumini', async (req, res) => {
  try {
    const snapshot = await db.collection('Alumini').get();
    const alumniList = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.status(200).json(alumniList);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Modifier un Alumni
app.put('/Alumini/:id', async (req, res) => {
  try {
    const id = req.params.id; // ID de l'Alumni
    const data = req.body; // Données mises à jour envoyées par Flutter
    await db.collection('Alumini').doc(id).update(data);
    res.status(200).json({ message: 'Alumini mis à jour avec succès !' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Supprimer un Alumni
app.delete('/alumini/:id', async (req, res) => {
  try {
    const id = req.params.id; // ID de l'Alumni
    await db.collection('Alumini').doc(id).delete();
    res.status(200).json({ message: 'Alumini supprimé avec succès !' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Route pour récupérer les informations d'un utilisateur
app.get('/alumni/:id', async (req, res) => {
  try {
    const userId = req.params.id;

    // 1. Vérifier dans la collection Alumini
    const alumniDoc = await db.collection('Alumini').doc(userId).get();
    if (alumniDoc.exists) {
      return res.send(alumniDoc.data());
    }

    // 2. Si non trouvé dans Alumini, vérifier dans la collection Admin
    const adminDoc = await db.collection('admin').doc(userId).get();
    if (adminDoc.exists) {
      return res.send(adminDoc.data());
    }

    // 3. Si non trouvé dans les deux collections, retourner une erreur 404
    return res.status(404).send({ message: 'Utilisateur non trouvé' });
  } catch (error) {
    res.status(500).send({ message: 'Erreur serveur', error: error.message });
  }
});



const JWT_SECRET = 'votre_secret_jwt';

/*-------------------------------------------------------------------------------------------------------------------*/


// Gérer les connexions Socket.io
/*io.on('connection', function (socket) {
    console.log('Un utilisateur est connecté:', socket.id);
    console.log('Un client est connecté');
    // Rejoindre une room spécifique à l'alumni
    socket.on('join_alumni_room', (alumniId) => {
      socket.join(alumniId);
      console.log(`Utilisateur ${socket.id} a rejoint la room ${alumniId}`);
    });

    // Gérer la déconnexion
    socket.on('disconnect', () => {
      console.log('Utilisateur déconnecté:', socket.id);
    });
  });*/

// Route pour envoyer un message
app.post('/messages', async (req, res) => {
  const { alumniId, sender, message } = req.body;

  if (!alumniId || !sender || !message) {
    return res.status(400).json({ error: 'alumniId, sender et message sont requis.' });
  }

  try {
    // Ajouter un message à la base de données
    const docRef = await db.collection('messages').add({
      alumniId,
      sender,
      message,
      timestamp: new Date().toISOString(),
    });

    // Émettre un événement Socket.io pour notifier les clients
    io.to(alumniId).emit('new_message', {
      id: docRef.id,
      alumniId,
      sender,
      message,
      timestamp: new Date().toISOString(),
    });

    return res.status(201).json({ id: docRef.id, message: 'Message envoyé avec succès.' });
  } catch (error) {
    console.error('Erreur lors de l\'envoi du message:', error);
    res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
});

// Route pour récupérer les messages liés à un alumni
app.get('/messages/:alumniId', async (req, res) => {
  const { alumniId } = req.params;

  if (!alumniId) {
    return res.status(400).json({ error: 'alumniId est requis.' });
  }

  try {
    // Récupérer les messages depuis la base de données
    const querySnapshot = await db.collection('messages').where('alumniId', '==', alumniId).orderBy('timestamp', 'asc').get();

    const messages = querySnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));

    return res.status(200).json(messages);
  } catch (error) {
    console.error('Erreur lors de la récupération des messages:', error);
    res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
});

/*-------partie evenement-------------------------------------------------------------------------------------------------------------*/

// Route pour ajouter un événement avec une image
app.post('/addEvents', upload.single('image'), async (req, res) => {
  try {
    const { title, description, date, location, postedDate } = req.body;
    const imageFile = req.file; // Fichier image uploadé

    console.log(req.file);
    console.log('Données reçues :', req.body);

    // Validation des données
    if (!title || !date) {
      return res.status(400).json({ error: 'Le titre et la date sont obligatoires.' });
    }

    // Encoder l'image en Base64 si elle est fournie
    let imageBase64 = 'Non spécifié';
    if (imageFile) {
      imageBase64 = imageFile.buffer.toString('base64'); // Convertir le fichier en Base64
    }

    // Nouvelle structure d'événement
    const newEvent = {
      title,
      description: description || 'Aucune description',
      date,
      location: location || 'Non spécifié',
      image: imageBase64, // Stocker l'image en Base64
      postedDate: postedDate || new Date().toISOString(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    console.log('Données préparées pour Firestore :', newEvent);
    // Ajout dans Firestore
    const eventsRef = await db.collection('events').add(newEvent);

    // Réponse avec l'ID généré
    res.status(201).json({ id: eventsRef.id, ...newEvent });
  } catch (error) {
    console.error('Erreur lors de l\'ajout de l\'événement :', error);
    res.status(500).json({ error: 'Erreur lors de l\'ajout de l\'événement' });
  }
});

app.get('/getevents', async (req, res) => {
  try {
    const snapshot = await db.collection('events').get(); // Récupérer les événements depuis Firestore
    const events = snapshot.docs.map(doc => {
      let eventData = doc.data();
      // Si l'événement a une image en base64, on peut la retourner avec les autres données
      if (eventData.image) {
        eventData.image = `data:image/jpeg;base64,${eventData.image}`; // Décode l'image en base64
      }
      return eventData;
    });
    res.json(events); // Retourner les événements sous forme de JSON
  } catch (error) {
    console.error('Erreur lors de la récupération des événements:', error);
    res.status(500).send('Erreur lors de la récupération des événements');
  }
});


/*---------------Statistique-----------------------------*/
app.get('/statistics', async (req, res) => {
  try {
    // Récupérer le nombre total des inscrits
    const alumniSnapshot = await db.collection('Alumini').get();
    // Récupérer les nombres des evenenemts
    const eventSnapshot = await db.collection('events').get();
    // Récupérer les offres d'emploi avec le statut "pending"
    const pendingOffersSnapshot = await db.collection('JobOffers')
      .where('status', '==', 'pending')
      .get();
    // Récupérer les offres d'emploi avec le statut "approved"
    const approvedOffersSnapshot = await db.collection('JobOffers')
      .where('status', '==', 'approved')
      .get();
    // Calculer le nombre total des alumni inscrits
    const alumniCount = alumniSnapshot.size;
    // Calculer le nombre d'offres pour chaque statut
    const eventCount = eventSnapshot.size;
    const pendingCount = pendingOffersSnapshot.size;
    const approvedCount = approvedOffersSnapshot.size;
    // Retourner les statistiques
    res.json({
      alumni_total_Count: alumniCount,
      event_total_count_Count: eventCount,
      pending_job_offers_count: pendingCount,
      approved_job_offers_count: approvedCount,
    });
  } catch (error) {
    console.error('Erreur lors de la récupération des statistiques', error);
    res.status(500).send('Erreur interne du serveur');
  }
});

// Récupérer les statistiques avec filtrage
app.get('/alumni', async (req, res) => {
  try {
    const { option } = req.query; // Option facultative
    const alumniSnapshot = await db.collection('Alumini').get();
    const stats = {};

    alumniSnapshot.forEach(doc => {
      const data = doc.data();

      // Vérifier si l'alumni est diplômé
      if (data.statut !== 'Diplômé') return; // Ignorer les non-diplômés

      // Filtrage par option (si une option est spécifiée)
      if (option && data.option !== option) return;

      const currentOption = data.option || 'Inconnu';
      const travaille = data.travail === 'Oui' ? 'travaillent' : 'Ne travaillent pas';

      // Initialiser l'option dans les stats si elle n'existe pas encore
      if (!stats[currentOption]) {
        stats[currentOption] = { 'travaillent': 0, 'Ne travaillent pas': 0 };
      }

      // Incrémenter le compteur correspondant
      stats[currentOption][travaille]++;
    });

    res.json(stats);
  } catch (error) {
    console.error(error);
    res.status(500).send('Erreur lors de la récupération des statistiques');
  }
});

app.get('/statusalumni', async (req, res) => {
  try {
    const alumniSnapshot = await db.collection('Alumini').get();
    const stats = {
      diplomes: { travaillent: 0, neTravaillentPas: 0 },
      etudiants: 0,
    };

    alumniSnapshot.forEach((doc) => {
      const data = doc.data();

      if (data.statut === 'Diplômé') {
        if (data.travail === 'Oui') {
          stats.diplomes.travaillent++;
        } else {
          stats.diplomes.neTravaillentPas++;
        }
      } else {
        stats.etudiants++;
      }
    });

    res.json(stats);
  } catch (error) {
    console.error(error);
    res.status(500).send('Erreur lors de la récupération des statistiques');
  }
});

/*-----------------Questions reponses--------------------------------*/
// Récupérer toutes les questions
app.get('/questions', async (req, res) => {
  try {
    console.log('Début de la récupération des questions...'); // Log 1

    const snapshot = await db.collection('questions').orderBy('timestamp', 'desc').get();
    console.log(`Nombre de questions trouvées : ${snapshot.size}`); // Log 2

    const questions = [];
    snapshot.forEach((doc) => {
      const data = doc.data();
      console.log(`Document ID : ${doc.id}`); // Log 3
      console.log('Données du document :', data); // Log 4

      const question = {
        id: doc.id,
        title: data.title || '',
        content: data.content || '', // Accédez directement à data.content
        author: data.authorName || '', // Accédez directement à data.authorName
        avatarUrl: data.authorAvatarUrl || '', // Accédez directement à data.authorAvatarUrl
        timestamp: data.timestamp || '', // Conservez le timestamp tel quel
      };
      questions.push(question);
    });

    console.log('Questions récupérées avec succès :', questions); // Log 5
    res.status(200).json(questions);
  } catch (error) {
    console.error('Erreur lors de la récupération des questions :', error); // Log 6
    res.status(500).send('Erreur lors de la récupération des questions');
  }
});

// Créer une snouvelle question
app.post('/questions', async (req, res) => {
  try {
    const { title, content, alumniId } = req.body;

    // Vérifier si l'alumni existe
    const alumniDoc = await db.collection('Alumini').doc(alumniId).get();
    if (!alumniDoc.exists) {
      console.log('Alumni non trouvé:', alumniId);
      return res.status(404).send('Alumni non trouvé');
    }

    // Ajouter la question
    const newQuestion = {
      title,
      content,
      alumniId,
      authorName: alumniDoc.data().nom, // Récupérer le nom de l'alumni
      authorAvatarUrl: alumniDoc.data().photo, // Récupérer l'URL de l'avatar
      timestamp: new Date().toISOString(), // Date et heure actuelles
    };

    console.log('Nouvelle question:', newQuestion);
    const docRef = await db.collection('questions').add(newQuestion);
    console.log('Question ajoutée avec succès:', docRef.id);
    res.status(201).json({ id: docRef.id, ...newQuestion });
  } catch (error) {
    console.error('Error adding question:', error);
    res.status(500).send('Erreur lors de l\'ajout de la question');
  }
});
 
app.get('/questions/:questionId/reponses', async (req, res) => {
  try {
    const questionId = req.params.questionId;
    console.log(`Récupération des réponses pour la question ID : ${questionId}`);

    const reponsesSnapshot = await db.collection('questions').doc(questionId).collection('replies').orderBy('timestamp', 'desc').get();
    const reponses = [];
    reponsesSnapshot.forEach((doc) => {
      const data = doc.data();
      reponses.push({
        id: doc.id,
        content: data.content || '',
        author: data.author || 'Auteur inconnu',
        avatarUrl: data.authorAvatarUrl || '',
        timestamp: data.timestamp || '',
      });
    });

    console.log('Réponses récupérées avec succès :', reponses);
    res.status(200).json(reponses);
  } catch (error) {
    console.error('Erreur lors de la récupération des réponses :', error);
    res.status(500).send('Erreur lors de la récupération des réponses');
  }
});

app.post('/questions/:questionId/reponses', async (req, res) => {
  try {
    const questionId = req.params.questionId;
    const { content, alumniId, author, avatarUrl } = req.body;

    console.log('Données reçues :', { questionId, content, alumniId, author, avatarUrl }); // Log 1

    // Vérifier si alumniId est défini
    if (!alumniId) {
      return res.status(400).json({ message: 'alumniId est manquant' }); // Renvoyer une réponse JSON
    }

    // Vérifier si l'alumni existe
    const alumniDoc = await db.collection('Alumini').doc(alumniId).get();
    if (!alumniDoc.exists) {
      console.log('Alumni non trouvé :', alumniId); // Log 2
      return res.status(404).json({ message: 'Alumni non trouvé' }); // Renvoyer une réponse JSON
    }

    // Vérifier si la question existe
    const questionDoc = await db.collection('questions').doc(questionId).get();
    if (!questionDoc.exists) {
      console.log('Question non trouvée :', questionId); // Log 3
      return res.status(404).json({ message: 'Question non trouvée' }); // Renvoyer une réponse JSON
    }

    // Ajouter la réponse
    const newReply = {
      content,
      alumniId,
      author,
      avatarUrl,
      timestamp: new Date().toISOString(),
    };
    const docRef = await db.collection('questions').doc(questionId).collection('replies').add(newReply);
    console.log('Réponse ajoutée avec ID :', docRef.id); // Log 4
    res.status(201).json({ id: docRef.id, ...newReply }); // Renvoyer une réponse JSON
  } catch (error) {
    console.error('Error adding reply:', error); // Log 5
    res.status(500).json({ message: 'Erreur lors de l\'ajout de la réponse' }); // Renvoyer une réponse JSON
  }
});


// Endpoint pour envoyer une notification
// Route pour envoyer un e-mail
/*app.post('/send-email', (req, res) => {
  const { email } = req.body;

  const mailOptions = {
    from: 'schoolprojecttest2@gmail.com',
    to: email,
    subject: 'Message de test',
    text: 'Ceci est un message de test envoyé depuis Node.js et Gmail.',
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Erreur lors de l\'envoi de l\'e-mail :', error);
      res.status(500).send('Erreur lors de l\'envoi de l\'e-mail');
    } else {
      console.log('E-mail envoyé :', info.response);
      res.status(200).send('E-mail envoyé avec succès');
    }
  });
});*/

// Configuration du transporteur nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'schoolprojecttest2@gmail.com',  // Adresse e-mail de l'expéditeur
    pass: 'qsat ntsu ivph nurj'  // Ton mot de passe ou mot de passe d'application
  }
});
// Configuration de multer pour gérer l'upload des fichiers
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');  // Dossier pour sauvegarder les fichiers
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));  // Renommer le fichier
  }
});
const uploade = multer({ storage: storage });
// Route pour envoyer l'email avec les pièces jointes
app.post('/send-email', uploade.fields([{ name: 'cv' }, { name: 'motivationLetter' }]), (req, res) => {
  const { email } = req.body;  // Récupérer l'email de l'expéditeur envoyé depuis l'interface
  const cvPath = req.files['cv'][0].path;  // Chemin du CV
  const motivationLetterPath = req.files['motivationLetter'][0].path;  // Chemin de la lettre de motivation
  // Définir les options de l'email
  const mailOptions = {
    from: email,  // L'email de l'expéditeur
    to: 'schoolprojecttest2@gmail.com',  // L'email du destinataire
    subject: 'Candidature avec CV et Lettre de Motivation',
    text: 'Veuillez trouver ci-joint mon CV et ma lettre de motivation.',
    replyTo: email, 
    attachments: [
      {
        filename: 'cv.pdf',
        path: cvPath
      },
      {
        filename: 'motivation_letter.pdf',
        path: motivationLetterPath
      }
    ]
  };

  // Envoi de l'email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Erreur lors de l\'envoi de l\'e-mail :', error);
      res.status(500).send('Erreur lors de l\'envoi de l\'e-mail');
    } else {
      console.log('E-mail envoyé :', info.response);
      res.status(200).send('E-mail envoyé avec succès');
    }
  });
});

// Démarrage du serveurs
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Serveur Node.js en cours d'exécution sur le port ${PORT}`);
});
