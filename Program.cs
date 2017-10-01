using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Tp1Secu
{
    class Program
    {
        static void Main(string[] args)
        {
            string Username;
            string Master_Pass;
            string Tag;
            int UserId;
            using (var db = new DatabaseContext())
            {
                switch(args[0]){
                    case "-r":
                        Username = args[1];
                        Master_Pass = args[2];
                        Register(db, Username, Master_Pass);
                    break;
                    case "-a":
                        Username = args[1];
                        Master_Pass = args[2];
                        Tag = args[3];
                        string NewPassword = args[4];
                        UserId = LoginUser(db, Username, Master_Pass);
                        if(UserId != 0){
                            AddPass(db, NewPassword, Tag, UserId);
                        }
                        else{
                            Console.WriteLine("ERROR : Acces refusé");
                        }
                    break;

                    case "-g": 
                        Username = args[1];
                        Master_Pass = args[2];
                        Tag = args[3];
                        UserId = LoginUser(db, Username, Master_Pass);
                        if(UserId != 0){
                            GetPass(db, Tag, UserId);
                        }
                        else{
                            Console.WriteLine("ERROR : Acces refusé");
                        }
                    break;
                    case "-d": 
                        Username = args[1];
                        Master_Pass = args[2];
                        Tag = args[3];
                        UserId = LoginUser(db, Username, Master_Pass); 
                        if(UserId != 0){ 
                            SuppPass(db, Tag);
                        }
                        else{
                            Console.WriteLine("ERROR : Acces refusé");
                        }
                    break;
                    case "-t": 
                        Username = args[1];
                        if (args.Length == 2)
                        {
                            string SaltHash = ReturnSaltHash(db, Username);
                            Console.WriteLine(SaltHash);
                        }
                        else if(args.Length == 3)
                        {
                            Tag = args[2];
                            string PassByTag = ReturnPassByTag(db,Tag);
                            Console.WriteLine(PassByTag);
                        }
                        else{
                            Console.WriteLine("ERROR : Trop d'arguments");
                        }
                    break;
                    default: 
                        Console.WriteLine("ERROR : Commande {0} non-reconnue", args[0]);
                    break;

                }
            }
        }
            static int LoginUser(DatabaseContext db, string User, string Pass){
                SHA256 mySHA256 = SHA256Managed.Create();

                string Salt;
                string PassCryptInput;
                string PassCryptDB;

                foreach(var Utilisateur in db.Users){
                    if(User == Utilisateur.UserName){
                        Salt = Utilisateur.UserSalt;
                        byte[] PassSaltInput = Encoding.ASCII.GetBytes(Pass + Salt);
                        PassCryptInput = Convert.ToBase64String(mySHA256.ComputeHash(PassSaltInput));
                        PassCryptDB = Utilisateur.UserPassword;
                        if(PassCryptInput == PassCryptDB){
                           int O = Utilisateur.UserId;
                            return O;    
                        }
                    }
                }
                return 0;
            }
            static void Register(DatabaseContext db, string User, string Pass){
                if(SearchUser(db, User) == ""){
                    SHA256 mySHA256 = SHA256Managed.Create();
                    RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                    int LongMax = 16;
                    byte[] Sel = new byte[LongMax];
                    rng.GetNonZeroBytes(Sel);

                    string SaveSalt = Convert.ToBase64String(Sel);
                    byte[] PassSalt = Encoding.ASCII.GetBytes(Pass + SaveSalt);
                    string PassCrypto = Convert.ToBase64String(mySHA256.ComputeHash(PassSalt));

                    db.Users.Add(new User {UserName = User, UserPassword = PassCrypto, UserSalt = SaveSalt}); 

                    db.SaveChanges();
                    Console.WriteLine("OK");
                }
                else{
                    Console.WriteLine("ERROR : USERNAME deja utilise");
                }
            }

        static void AddPass(DatabaseContext database, string NewPass, string NewTag, int UserId){
            //AES256 
            byte[] UserSalt = Convert.FromBase64String(database.Users.Find(UserId).UserSalt);
            string Pass = SearchPassWord(database, NewTag);
            if (Pass != ""){
                Console.WriteLine("ERROR : Le Tag est deja utilise. veuillez en choisir un autre");
            }
            else{
                string Key = GenerateKey(NewPass, UserSalt);
                string PassWord = EncryptString(NewPass, Key);
                database.Passwords.Add(new Pass { PassTag = NewTag, PassKey = Key, Password = PassWord });
                database.SaveChanges();
                Console.WriteLine("OK");
            }
        }
        static void GetPass(DatabaseContext database, string Tag, int UserId){
                byte[] UserSalt = Convert.FromBase64String(database.Users.Find(UserId).UserSalt);
                string Pass = SearchPassWord(database, Tag);
                    if (Pass != ""){//il existe
                        string IV = Pass.Split(' ')[0];
                        string PassKey = SearchPassKey(database, Tag);
                        string PassCrypt = Pass.Split(' ')[1];
                string PassWordDecrypt = DecryptString(PassCrypt, PassKey, IV);
                Console.WriteLine(PassWordDecrypt);
                }
                else{
                    Console.WriteLine("ERROR : TAG non reconnu");
                }
        }

        static string ReturnSaltHash(DatabaseContext database, string UserLogin){
            foreach (var User in database.Users){
                if (User.UserName == UserLogin){
                    return User.UserSalt + ":" + User.UserPassword;
                }
            }
            return "ERROR : USERNAME non reconnu";
        }
        static string SearchUser(DatabaseContext database, string UserLogin){
            foreach (var User in database.Users){
                if (User.UserName == UserLogin){
                    return User.UserName;
                }
            }
            return "";
        }

        static string ReturnPassByTag(DatabaseContext database, string TagArg)
        {
            foreach (var Tag in database.Passwords)
            {
                if (Tag.PassTag == TagArg)
                {
                    return Tag.Password;
                }
            }
            return "ERROR : TAG non reconnu";
        }

        static string GenerateKey(string Pass, byte[] UserSalt){
            string Key = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: Pass,
            salt: UserSalt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 10000,
            numBytesRequested: 256 / 8));
            return Key;
        }
        static void SuppPass(DatabaseContext database, string Tag){
            if(SearchPassWord(database, Tag) != ""){
                foreach(var Mdp in database.Passwords){
                    if(Mdp.PassTag == Tag){
                        database.Remove(Mdp);
                        database.SaveChanges();
                    }
                }
                Console.WriteLine("OK");
            }else{
                Console.WriteLine("ERROR : Tag non reconnu");
            }
        }
            static string SearchPassWord(DatabaseContext database, string Tag){
                foreach(var Mdp in database.Passwords){
                    if(Mdp.PassTag == Tag){
                        return Mdp.Password;
                    }
                }
                return "";
            }
            static string SearchPassKey(DatabaseContext database, string Tag){
                foreach(var Mdp in database.Passwords){
                    if(Mdp.PassTag == Tag){
                        return Mdp.PassKey;
                    }
                }
                return "";
            }

        private static string EncryptString(string clearText, string strKey)
        {
            // Place le texte à chiffrer dans un tableau d'octets
            byte[] plainText = Encoding.UTF8.GetBytes(clearText);

            // Place la clé de chiffrement dans un tableau d'octets
            //byte[] key = Encoding.UTF8.GetBytes(strKey);
            byte[] key = Convert.FromBase64String(strKey);

            // Place le vecteur d'initialisation dans un tableau d'octets
            byte[] iv;
            using (Aes myAes = Aes.Create())
            {
                iv = myAes.IV;
            }

            RijndaelManaged rijndael = new RijndaelManaged();

            // Définit le mode utilisé
            rijndael.Mode = CipherMode.CBC;

            // Crée le chiffreur AES - Rijndael
            ICryptoTransform aesEncryptor = rijndael.CreateEncryptor(key, iv);

            MemoryStream ms = new MemoryStream();

            // Ecris les données chiffrées dans le MemoryStream
            CryptoStream cs = new CryptoStream(ms, aesEncryptor, CryptoStreamMode.Write);
            cs.Write(plainText, 0, plainText.Length);
            cs.FlushFinalBlock();

            // Place les données chiffrées dans un tableau d'octet
            byte[] CipherBytes = ms.ToArray();

            ms.Close();
            cs.Close();

            // Place les données chiffrées dans une chaine encodée en Base64
            return Convert.ToBase64String(iv) + " " + Convert.ToBase64String(CipherBytes);
        }

        public static string DecryptString(string cipherText, string strKey, string strIv)
        {

            // Place le texte à déchiffrer dans un tableau d'octets
            byte[] cipheredData = Convert.FromBase64String(cipherText);

            // Place la clé de déchiffrement dans un tableau d'octets
            byte[] key = Convert.FromBase64String(strKey);

            // Place le vecteur d'initialisation dans un tableau d'octets
            byte[] iv = Convert.FromBase64String(strIv);

            RijndaelManaged rijndael = new RijndaelManaged();
            rijndael.Mode = CipherMode.CBC;


            // Ecris les données déchiffrées dans le MemoryStream
            ICryptoTransform decryptor = rijndael.CreateDecryptor(key, iv);
            MemoryStream ms = new MemoryStream(cipheredData);
            CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

            // Place les données déchiffrées dans un tableau d'octet
            byte[] plainTextData = new byte[cipheredData.Length];

            int decryptedByteCount = cs.Read(plainTextData, 0, plainTextData.Length);

            ms.Close();
            cs.Close();

            return Encoding.UTF8.GetString(plainTextData, 0, decryptedByteCount);
        }
    }
}
