"""imports"""
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
import sys
import os

"""Classes/Functions"""

def center(Widget, x, y):
    """
    Center the widget to the middle of the users screen
    Also allocates locked size
    """
    Widget.resize(x, y)
    Widget.setMinimumWidth(x)
    Widget.setMaximumWidth(x)
    Widget.setMinimumHeight(y)
    Widget.setMaximumHeight(y)
    qr = Widget.frameGeometry()
    cp = QDesktopWidget().availableGeometry().center()
    qr.moveCenter(cp)
    Widget.move(qr.topLeft())

class Functions:
    def RSAGenerate(self, Phrase, FIle):
        """
        Generate the RSA key with the given passphrase
        Output the key in the desired location
        """
        key = RSA.generate(2048)
        encKey = key.exportKey(passphrase=Phrase, 
            pkcs=8, protection="scryptAndAES256-CBC") #AES256 bit secure
        with open(File, "wb") as F:
            F.write(encKey)

        with open(File, "rb") as F:
            encodedKey = F.read()
            key = RSA.import_key(encodedKey, 
                passphrase=Phrase)

            with open(File+".pem","wb") as L: #Write the public key to file
                L.write(key.publickey().exportKey())

        sys.exit()

    def CreatePublic(self, Passphrase, File):
        """
        Create a public key from the users private key with the phrase included
        """    
        PrivKey = open(File, "rb")
        Key = RSA.import_key(PrivKey.read(), 
            passphrase=Passphrase)
        with open(File+".pem", "wb") as F:
            F.write(Key.publickey().exportKey())
        sys.exit()

    def EncryptFile(self, InFile, KeyFile, Overwrite=None):
        """
        Encrypt the given file
        Outputs the file with option to overwrite TBF
        """
        if Overwrite: #do this later
            pass

        else:
            pass
        EncFile = open(InFile+".bin","wb")
        Key = RSA.import_key(open(KeyFile).read()) #Import the users public key
        session_key = get_random_bytes(16)
        ciphered = PKCS1_OAEP.new(Key)
        EncFile.write(ciphered.encrypt(session_key))
        cipher_AES = AES.new(session_key,AES.MODE_EAX)
        ciphertext, tag = cipher_AES.encrypt_and_digest(open(InFile,"rb").read())
        [EncFile.write(x) for x in (cipher_AES.nonce, tag, ciphertext)]
        sys.exit()

    def DecryptFile(self, EncFile, KeyFile, Passphrase, Overwrite=None):
        """
        Decrypt the users file with the private key and passphrase
        """
        if Overwrite:
            pass

        else:
            pass
        PrivateKey = KeyFile
        Phrase = Passphrase
        KeyFile = open(PrivateKey,'rb')        
        PrivateKey = RSA.import_key(KeyFile.read(),
            passphrase=Phrase) #Import the user private key
        KeyFile.close()
        with open(EncFile,"rb") as File:
            enc_session_key, nonce, tag, ciphertext = \
               [File.read(x) for x in (PrivateKey.size_in_bytes(), 16, 16, -1)]
            cipher_rsa = PKCS1_OAEP.new(PrivateKey)
            session_key = cipher_rsa.decrypt(enc_session_key)
            cipher_aes = AES.new(session_key,AES.MODE_EAX, nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        with open(EncFile+".dec","wb") as F:
            F.write(data)
        sys.exit()

class RSAMenu(QWidget):

    def __init__(self):
        super().__init__()
        center(self, 400, 250)
        self.menuInit()

    def GetEntries(self):
        self.Passphrase = self.PassEntry.text()
        self.SaveName = self.SaveEntry.text()

        if not self.Passphrase:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("No Passphrase given!")
            ErrorBox.setText("No Passphrase entered.")
            ErrorBox.setInformativeText("A Passphrase is required.")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        else:
            pass

        if not self.SaveName:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("No save name given!")
            ErrorBox.setText("No save name entered.")
            ErrorBox.setInformativeText("A save name is required.")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        else:
            pass

        self.hide()
        Funcs = Functions()
        Funcs.RSAGenerate(self.Passphrase, self.SaveName)
        self.hide()

    def GetFileDirectory(self):
        Dialog = QFileDialog()
        Dialog.setFileMode(QFileDialog.Directory)

        if Dialog.exec_():
            self.FilePath = Dialog.selectedFiles()
            os.chdir(self.FilePath[0])

        else:
            pass


    def menuInit(self):
        self.FilePath = os.getcwd()
        self.setWindowTitle("RSA Menu")
        self.setWindowIcon(QIcon("logo.ico"))
        self.setStyleSheet("QWidget {Background-color: rgb(14, 121, 214);}")
        PassLabel = QLabel("Passphrase:", self)
        PassLabel.move(200 - PassLabel.width(), 5)
        self.PassEntry = QLineEdit(self)
        self.PassEntry.setEchoMode(QLineEdit.Password)
        self.PassEntry.move(200 - self.PassEntry.width() * 1.6,
         PassLabel.y() + PassLabel.height() + 5)
        self.PassEntry.setStyleSheet("QLineEdit {Background-color: rgb(255,255,255);}")
        self.DirectoryButton = QPushButton("Choose directory", self)
        self.DirectoryButton.move((200 - self.DirectoryButton.width() * 1.4),
         self.PassEntry.y() + self.PassEntry.height()+ 5)
        self.DirectoryButton.clicked.connect(self.GetFileDirectory)
        self.DirectoryButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        SaveLabel = QLabel("Save name:", self)
        SaveLabel.move(200 - SaveLabel.width(),
         self.DirectoryButton.y() + self.DirectoryButton.height() + 15)
        self.SaveEntry = QLineEdit(self)
        self.SaveEntry.move(200 - self.SaveEntry.width() * 1.6,
         SaveLabel.y() + SaveLabel.height() + 5)
        self.SaveEntry.setStyleSheet("QLineEdit {Background-color: rgb(255,255,255);}")
        EntryButton = QPushButton("Create", self)
        EntryButton.move(200 - EntryButton.width() * 0.6,
          self.SaveEntry.y() + self.SaveEntry.height() + 5)
        EntryButton.clicked.connect(self.GetEntries)
        EntryButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.show()

class PublicMenu(QWidget):

    def __init__(self):

        super().__init__()
        center(self, 340, 180)
        self.MenuInit()

    def GetFile(self):
        Get = QFileDialog()
        Get.setFileMode(QFileDialog.AnyFile)

        if Get.exec_():
            self.File = Get.selectedFiles()[0]

        else:
            """
            Create error box for no file present
            """
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("No file selected")
            ErrorBox.setText("Please select a private key")
            ErrorBox.setInformativeText("No file selected")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        self.Passphrase = self.PassEntry.text()

        if not self.Passphrase:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("No key entered")
            ErrorBox.setText("Please enter a key")
            ErrorBox.setInformativeText("No key enetered")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        else:
            pass

        try:
            PrivKey = open(self.File, "rb")

        except:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("File Error")
            ErrorBox.setText("File could not be opened")
            ErrorBox.setInformativeText("Error opening file")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        try:
            Key = RSA.import_key(PrivKey.read(), 
                passphrase=self.Passphrase)

        except ValueError:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("Invalid Passphrase")
            ErrorBox.setText("Passphrase incorrect")
            ErrorBox.setInformativeText("Error with passphrase")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        Funcs = Functions()
        Funcs.CreatePublic(self.Passphrase, self.File)
        sys.exit()

    def MenuInit(self):

        self.setWindowTitle("Public Key Menu")
        self.setWindowIcon(QIcon("logo.ico"))
        self.setStyleSheet("QWidget {Background-color: rgb(14, 121, 214);}")
        PassLabel = QLabel("Passphrase:", self)
        PassLabel.move((170 - PassLabel.width()),10)
        self.PassEntry = QLineEdit(self)
        self.PassEntry.setStyleSheet("QLineEdit {Background-color: rgb(255,255,255);}")
        self.PassEntry.setEchoMode(QLineEdit.Password)
        self.PassEntry.move((170 - self.PassEntry.width() * 1.6),
         PassLabel.y() + PassLabel.height() + 5)
        FileButton = QPushButton("Choose Private Key", self)
        FileButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        FileButton.move((170 - FileButton.width() * 1.62),
         self.PassEntry.y() + self.PassEntry.height() + 5)
        FileButton.clicked.connect(self.GetFile)
        self.show()

class EncryptMenu(QWidget):

    def __init__(self):

        super().__init__()
        self.File = None
        self.KeyFile = None
        center(300, 200)
        self.EncryptMenu()

    def GetFile(self):
        Get = QFileDialog()
        Get.setFileMode(QFileDialog.AnyFile)

        if Get.exec_():
            self.File = Get.selectedFiles()[0]

        else:
            return

    def GetKey(self):
        Get = QFileDialog()
        Get.setFileMode(QFileDialog.AnyFile)

        if Get.exec_():
            self.KeyFile = Get.selectedFiles()[0]

        else:
            return

    def EncryptSubmit(self):
        if not self.File:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("No file selected")
            ErrorBox.setText("Please choose a file")
            ErrorBox.setInformativeText("No file was chosen")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        else:
            pass

        if not self.KeyFile:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("No key given")
            ErrorBox.setText("Please select a key")
            ErrorBox.setInformativeText("No key was selected")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        else:
            pass

        try:
            RSAKey = RSA.import_key(open(self.KeyFile).read())

        except ValueError:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("Invalid Key")
            ErrorBox.setText("Error when importing key. Possibly private")
            ErrorBox.setInformativeText("Key could not be imported")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        Funcs = Functions()
        Funcs.EncryptFile(self.File, self.KeyFile)
        sys.exit()

    def EncryptMenu(self):
        self.setWindowIcon(QIcon("logo.ico"))
        self.setWindowTitle("Encrypt File")
        self.setStyleSheet("QWidget {Background-color: rgb(14, 121, 214);}")
        self.FileButton = QPushButton("Choose file", self)
        self.FileButton.setGeometry(0, 5, 300, 60)
        self.FileButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.FileButton.clicked.connect(self.GetFile)
        self.KeyButton = QPushButton("Choose RSA Key", self)
        self.KeyButton.setGeometry(0, 70, 300, 60)
        self.KeyButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.KeyButton.clicked.connect(self.GetKey)
        self.SubmitButton = QPushButton("Submit", self)
        self.SubmitButton.setGeometry(0, 135, 300, 60)
        self.SubmitButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.SubmitButton.clicked.connect(self.EncryptSubmit)
        self.show()

class DecryptMenu(QWidget):

    def __init__(self):

        super().__init__()
        self.File = None
        self.KeyFile = None
        self.Passphrase = None
        center(350, 300)
        self.DecryptMenu()

    def GetFile(self):
        Get = QFileDialog()
        Get.setFileMode(QFileDialog.AnyFile)

        if Get.exec_():
            self.File = Get.selectedFiles()[0]

        else:
            return

    def GetKey(self):
        Get = QFileDialog()
        Get.setFileMode(QFileDialog.AnyFile)

        if Get.exec_():
            self.KeyFile = Get.selectedFiles()[0]

        else:
            return

    def DecryptSubmit(self):
        self.Passphrase = self.PassEntry.text()
        if not self.Passphrase:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("No passphrase entered")
            ErrorBox.setText("Please enter a passphrase")
            ErrorBox.setInformativeText("No passphrase was given")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        else:
            pass


        if not self.File:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("No file selected")
            ErrorBox.setText("Please choose a file")
            ErrorBox.setInformativeText("No file was chosen")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        else:
            pass


        if not self.KeyFile:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("No key given")
            ErrorBox.setText("Please select a key")
            ErrorBox.setInformativeText("No key was selected")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        else:
            pass


        try:
            F = open(self.KeyFile, "rb")
            RSA.import_key(F.read(),passphrase=self.Passphrase)
            F.close()

        except FileNotFoundError:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("Error Opening File")
            ErrorBox.setText("The given file could not be opened")
            ErrorBox.setInformativeText("Invalid file")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        except ValueError:
            ErrorBox = QMessageBox(self)
            ErrorBox.setIcon(QMessageBox.Warning)
            ErrorBox.setWindowTitle("Invalid passphrase")
            ErrorBox.setText("The given passphrase is incorrect")
            ErrorBox.setInformativeText("Incorrect passphrase")
            ErrorBox.setStandardButtons(QMessageBox.Abort)
            ErrorBox.buttonClicked.connect(sys.exit)
            ErrorBox.exec_()
            sys.exit()

        self.hide()
        Funcs = Functions()
        Funcs.DecryptFile(self.File, self.KeyFile, self.Passphrase)
        sys.exit()

        

    def DecryptMenu(self):
        self.setWindowIcon(QIcon("logo.ico"))
        self.setWindowTitle("Decrypt File")
        self.setStyleSheet("QWidget {Background-color: rgb(14, 121, 214);}")
        self.FileButton = QPushButton("Choose file", self)
        self.FileButton.setGeometry(25,5,300,60)
        self.FileButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.FileButton.clicked.connect(self.GetFile)
        self.KeyButton = QPushButton("Choose Key", self)
        self.KeyButton.setGeometry(25,70,300,60)
        self.KeyButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.KeyButton.clicked.connect(self.GetKey)
        self.PassLabel = QLabel("Passphrase:", self)
        self.PassLabel.setGeometry(75,130,300,30)
        self.PassLabel.setStyleSheet("QLabel {Background-color: rgba(255, 255, 255, 0);}")
        self.PassEntry = QLineEdit(self)
        self.PassEntry.setEchoMode(QLineEdit.Password)
        self.PassEntry.setGeometry(25,165,300,60)
        self.PassEntry.setStyleSheet("QLineEdit {Background-color: rgb(255,255,255);}")
        self.SubmitButton = QPushButton("Submit", self)
        self.SubmitButton.setGeometry(25,230,300,60)
        self.SubmitButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.SubmitButton.clicked.connect(self.DecryptSubmit)
        self.show()


class Base(QWidget):

    def __init__(self):
        """
        Initialise main menu class with fonts set
        """
        super().__init__()
        QFontDatabase.addApplicationFont("Font/Walkway Expand UltraBold.ttf")
        QApplication.setFont(QFont("Walkway Expand UltraBold", 20))
        self.mainInit()

    def CreateRSA(self):
        self.RSAMenu = RSAMenu()
        self.hide()

    def PublicKey(self):
        self.PublicMenu = PublicMenu()
        self.hide()

    def Encrypt(self):
        self.EncryptMenu = EncryptMenu()
        self.hide()

    def Decrypt(self):
        self.DecryptMenu = DecryptMenu()
        self.hide()


    def mainInit(self):
        """
        Set up for the main menu window
        """
        center(self, 600, 500)
        self.setWindowTitle("PyCrypt")
        self.setWindowIcon(QIcon("logo.ico"))
        Logo = QLabel(self)
        Image = QPixmap("logoSmall.png")
        Logo.setPixmap(Image)
        PictureLocation = [300 - Image.size().width()/2, 15]
        Logo.move(PictureLocation[0], PictureLocation[1])
        Text = QLabel("Welcome to PyCrypt:",self)
        Text.move(PictureLocation[0] - Text.width(), PictureLocation[1] + Image.size().height() +  10)
        self.setStyleSheet("QWidget {Background-color: rgb(14, 121, 214);}")
        self.RSAKeyButton = QPushButton("Create RSA Key", self)
        self.RSAKeyButton.setGeometry(150,
            (Text.pos().y() + Text.height() + 10), 300,50)
        self.RSAKeyButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.RSAKeyButton.clicked.connect(self.CreateRSA)
        self.PublicButton = QPushButton("Create public key", self)
        self.PublicButton.setGeometry(150,
            (self.RSAKeyButton.y() + self.RSAKeyButton.height()),300, 50)
        self.PublicButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.PublicButton.clicked.connect(self.PublicKey)
        self.EncryptButton = QPushButton("Encrypt file", self)
        self.EncryptButton.setGeometry(150,
            (self.PublicButton.y() + self.PublicButton.height()),300, 50)
        self.EncryptButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.EncryptButton.clicked.connect(self.Encrypt)
        self.DecryptButton = QPushButton("Decrypt file", self)
        self.DecryptButton.setGeometry(150,
            (self.EncryptButton.y()+self.EncryptButton.height()),300,50)
        self.DecryptButton.setStyleSheet("QPushButton {Background-color: rgb(23, 46, 216);}")
        self.DecryptButton.clicked.connect(self.Decrypt)
        self.show()

"""main"""

if __name__ == "__main__":
    app = QApplication(sys.argv)
    Window = Base()
    sys.exit(app.exec_())
