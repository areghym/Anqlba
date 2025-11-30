import React, { useState, useEffect, useCallback } from 'react';
import { initializeApp } from 'firebase/app';
import { 
  getAuth, 
  signInAnonymously, 
  signInWithCustomToken, 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword, 
  signOut,
  onAuthStateChanged 
} from 'firebase/auth';
import { 
  getFirestore, 
  doc, 
  setDoc, 
  onSnapshot, 
  getDoc,
  collection 
} from 'firebase/firestore';

// --- Firebase and Global Variable Initialization ---
const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : null;
const initialAuthToken = typeof __initial_auth_token !== 'undefined' ? __initial_auth_token : null;

let app;
let auth;
let db;

if (firebaseConfig) {
  try {
    app = initializeApp(firebaseConfig);
    auth = getAuth(app);
    db = getFirestore(app);
  } catch (error) {
    console.error("Firebase initialization failed:", error);
  }
}

// Function to handle authentication setup
const setupAuth = async (authInstance) => {
  if (initialAuthToken) {
    try {
      await signInWithCustomToken(authInstance, initialAuthToken);
      console.log("Signed in with initial custom token.");
    } catch (e) {
      console.error("Custom token sign-in failed. Attempting anonymous sign-in.", e);
      await signInAnonymously(authInstance);
    }
  } else {
    await signInAnonymously(authInstance);
    console.log("Signed in anonymously.");
  }
};

// --- Components ---

// Custom Modal Component for displaying messages (instead of alert())
const Modal = ({ message, onClose }) => {
  if (!message) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900 bg-opacity-70 backdrop-blur-sm p-4">
      <div className="bg-white dark:bg-gray-800 p-6 rounded-xl shadow-2xl max-w-sm w-full transform transition-all duration-300 scale-100">
        <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Notification</h3>
        <p className="text-gray-600 dark:text-gray-300 mb-6">{message}</p>
        <button
          onClick={onClose}
          className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 rounded-lg transition duration-200 shadow-md"
        >
          Close
        </button>
      </div>
    </div>
  );
};

const AuthForm = ({ type, onAuthSuccess, onShowMessage }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const isSignUp = type === 'signup';
  const title = isSignUp ? 'Create Account' : 'Sign In';
  const buttonText = isSignUp ? 'Sign Up' : 'Log In';

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!auth) {
      onShowMessage("Authentication service not initialized.");
      return;
    }

    setIsLoading(true);
    try {
      let userCredential;
      if (isSignUp) {
        userCredential = await createUserWithEmailAndPassword(auth, email, password);
        // After successful sign-up, create a document for the user in Firestore
        const userDocRef = doc(db, `artifacts/${appId}/users/${userCredential.user.uid}/user_data/profile`);
        await setDoc(userDocRef, {
          email: userCredential.user.email,
          createdAt: new Date().toISOString(),
          appId: appId
        });
        onShowMessage("Account created successfully! You are now logged in.");
      } else {
        userCredential = await signInWithEmailAndPassword(auth, email, password);
        onShowMessage("Logged in successfully!");
      }
      onAuthSuccess(userCredential.user.uid);

    } catch (error) {
      console.error("Authentication Error:", error);
      let errorMessage = "An unknown error occurred during authentication.";
      switch (error.code) {
        case 'auth/email-already-in-use':
          errorMessage = 'This email address is already in use.';
          break;
        case 'auth/invalid-email':
          errorMessage = 'The email address is not valid.';
          break;
        case 'auth/weak-password':
          errorMessage = 'The password should be at least 6 characters.';
          break;
        case 'auth/user-not-found':
        case 'auth/wrong-password':
          errorMessage = 'Invalid credentials. Please check your email and password.';
          break;
        default:
          errorMessage = `Authentication failed: ${error.message}`;
      }
      onShowMessage(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md p-8 space-y-6 bg-white dark:bg-gray-800 shadow-2xl rounded-2xl border border-gray-100 dark:border-gray-700">
      <h2 className="text-3xl font-extrabold text-gray-900 dark:text-white text-center">{title}</h2>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Email Address
          </label>
          <input
            id="email"
            name="email"
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg shadow-sm focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white placeholder-gray-400"
            placeholder="you@example.com"
            disabled={isLoading}
          />
        </div>
        <div>
          <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            required
            autoComplete={isSignUp ? "new-password" : "current-password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg shadow-sm focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white placeholder-gray-400"
            placeholder="••••••••"
            disabled={isLoading}
          />
        </div>
        <div>
          <button
            type="submit"
            className={`w-full flex justify-center items-center py-2 px-4 border border-transparent rounded-lg shadow-lg text-lg font-semibold text-white transition duration-300 ${
              isLoading
                ? 'bg-indigo-400 cursor-not-allowed'
                : 'bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500'
            }`}
            disabled={isLoading}
          >
            {isLoading ? (
              <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            ) : (
              buttonText
            )}
          </button>
        </div>
      </form>
    </div>
  );
};

const Dashboard = ({ user, onLogout, onShowMessage }) => {
  const [profile, setProfile] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch user profile data from Firestore
  useEffect(() => {
    if (!db || !user?.uid) return;
    
    // Path for private user data: /artifacts/{appId}/users/{userId}/user_data/profile
    const docRef = doc(db, `artifacts/${appId}/users/${user.uid}/user_data/profile`);
    
    // Set up real-time listener
    const unsubscribe = onSnapshot(docRef, (docSnap) => {
      if (docSnap.exists()) {
        setProfile(docSnap.data());
      } else {
        console.log("No profile data found. This is normal right after creation.");
      }
      setIsLoading(false);
    }, (error) => {
      console.error("Error listening to profile data:", error);
      onShowMessage(`Failed to load data: ${error.message}`);
      setIsLoading(false);
    });

    // Cleanup subscription on unmount
    return () => unsubscribe();
  }, [user?.uid, onShowMessage]);


  return (
    <div className="w-full max-w-3xl p-8 space-y-8 bg-white dark:bg-gray-800 shadow-2xl rounded-2xl border border-gray-100 dark:border-gray-700">
      <div className="flex justify-between items-start">
        <h2 className="text-3xl font-extrabold text-indigo-600 dark:text-indigo-400">
          User Dashboard
        </h2>
        <button
          onClick={onLogout}
          className="px-4 py-2 border border-transparent rounded-lg text-sm font-medium text-white bg-red-600 hover:bg-red-700 transition duration-200"
        >
          Sign Out
        </button>
      </div>

      <div className="space-y-4">
        <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-xl shadow-inner">
          <p className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
            Authentication Details:
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-300 break-all">
            <span className="font-medium text-gray-700 dark:text-gray-200">User ID (UID):</span> {user.uid}
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-300 break-all">
            <span className="font-medium text-gray-700 dark:text-gray-200">Email:</span> {user.email || 'N/A (Anonymous/Unverified)'}
          </p>
        </div>

        <div className="bg-gray-50 dark:bg-gray-700 p-6 rounded-xl shadow-inner min-h-[150px]">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
            Stored Profile Data:
          </h3>
          {isLoading ? (
            <p className="text-gray-500 dark:text-gray-400">Loading user profile...</p>
          ) : profile ? (
            <div className="space-y-1 text-sm text-gray-600 dark:text-gray-300">
              <p><span className="font-medium">Account Email:</span> {profile.email}</p>
              <p><span className="font-medium">Created At:</span> {new Date(profile.createdAt).toLocaleString()}</p>
              <p className='text-xs text-gray-400'>
                This data is securely stored in Firestore under your private path.
              </p>
            </div>
          ) : (
            <p className="text-gray-500 dark:text-gray-400">No custom profile data found yet.</p>
          )}
        </div>
        
        <div className="mt-6 p-4 border border-indigo-200 dark:border-indigo-700 rounded-lg bg-indigo-50 dark:bg-indigo-900/30">
            <h4 className="font-bold text-indigo-700 dark:text-indigo-300">Security Note</h4>
            <p className="text-sm text-indigo-600 dark:text-indigo-400">
                This application uses Firebase Authentication for secure user management and Firestore to store private user data persistently.
            </p>
        </div>
      </div>
    </div>
  );
};


// --- Main Application Component ---

const App = () => {
  const [currentUser, setCurrentUser] = useState(null);
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [currentView, setCurrentView] = useState('login'); // 'login' or 'signup'
  const [modalMessage, setModalMessage] = useState(null);

  const handleShowMessage = (message) => {
    setModalMessage(message);
  };

  const handleAuthSuccess = (uid) => {
    // onAuthStateChanged handles setting the user, but we can log success here
    console.log(`User authenticated with UID: ${uid}`);
    // No need to change view as onAuthStateChanged will handle the UI update
  };

  const handleLogout = useCallback(async () => {
    if (auth) {
      try {
        await signOut(auth);
        // After explicit sign-out, re-establish the anonymous session for Firestore access
        await signInAnonymously(auth);
        handleShowMessage("You have been signed out.");
        // onAuthStateChanged will update currentUser to the anonymous user
      } catch (error) {
        console.error("Logout Error:", error);
        handleShowMessage(`Logout failed: ${error.message}`);
      }
    }
  }, []);

  // 1. Firebase Initialization and Authentication Listener
  useEffect(() => {
    if (!auth || !db) {
      handleShowMessage("Firebase is not configured. Check the console for errors.");
      setIsAuthReady(true);
      return;
    }

    // Initialize platform token/anonymous sign-in
    setupAuth(auth).then(() => {
      console.log("Initial Firebase setup complete.");
    }).catch(e => {
      console.error("Error during initial setup:", e);
    });

    // Set up authentication state listener
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      if (user && user.email) {
        // Only set user if they are a real signed-in user (not anonymous)
        setCurrentUser(user);
        console.log("User state changed to authenticated email user:", user.uid);
      } else {
        // If no email, it's either logged out or an anonymous user
        // We still capture the user object to get the anonymous UID if needed for public data
        setCurrentUser(user); 
        console.log("User state changed to anonymous or logged out.");
      }
      setIsAuthReady(true);
    });

    // Cleanup subscription
    return () => unsubscribe();
  }, []);

  if (!isAuthReady) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 transition-colors duration-300">
        <div className="flex flex-col items-center">
          <svg className="animate-spin h-8 w-8 text-indigo-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <p className="mt-4 text-gray-600 dark:text-gray-300">Initializing Authentication Service...</p>
        </div>
        <Modal message={modalMessage} onClose={() => setModalMessage(null)} />
      </div>
    );
  }

  // Check if a non-anonymous user is signed in
  const isAuthenticated = currentUser && currentUser.email;

  const renderAuthView = () => (
    <div className="mt-8 flex flex-col items-center">
      {currentView === 'login' ? (
        <AuthForm type="login" onAuthSuccess={handleAuthSuccess} onShowMessage={handleShowMessage} />
      ) : (
        <AuthForm type="signup" onAuthSuccess={handleAuthSuccess} onShowMessage={handleShowMessage} />
      )}
      
      <div className="mt-4">
        <button
          onClick={() => setCurrentView(currentView === 'login' ? 'signup' : 'login')}
          className="text-sm font-medium text-indigo-600 hover:text-indigo-500 dark:text-indigo-400 dark:hover:text-indigo-300 transition duration-200"
        >
          {currentView === 'login'
            ? "Don't have an account? Sign Up"
            : "Already have an account? Log In"}
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col items-center justify-center p-4 transition-colors duration-300 font-sans">
      <h1 className="text-4xl font-bold text-gray-800 dark:text-gray-100 mb-8 mt-4">
        User Authentication Service
      </h1>
      
      {isAuthenticated ? (
        <Dashboard user={currentUser} onLogout={handleLogout} onShowMessage={handleShowMessage} />
      ) : (
        renderAuthView()
      )}
      
      <Modal message={modalMessage} onClose={() => setModalMessage(null)} />
      
      <div className="mt-8 p-4 bg-white dark:bg-gray-800 rounded-lg shadow-lg text-sm text-gray-500 dark:text-gray-400">
        Current App ID: <span className="font-mono text-xs break-all">{appId}</span>
      </div>
    </div>
  );
};

export default App;