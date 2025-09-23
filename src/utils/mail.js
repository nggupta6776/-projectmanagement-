import Mailgen from "mailgen";
import nodemailer from "nodemailer"

const sendemail = async (options) => {
    const mailGenerator = 
    new Mailgen({
        theme: "default",
        product:{
            name: "Task Manager",
            link: "https://taskmanagellink.com"
        }

    })
   
   const emailTextual = mailGenerator.generatePlaintext(options.mailgenContent)

      const emailHtml = mailGenerator.generatext(options.mailgenContent)

     const transporter =  nodemailer.createTransport({
        host: process.env.MAILTRAP_SMTP_HOST,
        port: process.env.MAILTRAP_SMTP_PORT,
        auth: {
            user:process.env.MAILTRAP_SMTP_USER,
            pass: process.env.MAILTRAP_SMTP_PASS
        }
      })

      const mail = {
        from: "mail.taskmanager@example.com",
        to:options.email,
        subject: options.subject,
        text: emailTextual,
        html: emailHtml 
        
      }

      try {
        await transporter.sendMail(mail)
      } catch (error) {
        console.error("Email service failed siliently.Make sure that you have provided your MAILTRAP credentials in the .env file")
        console.error("Error:", error)
      }
}

const emailVerificationMailgenContent = (username, verificationUrl) => {
    return {
        body: {
            name: username,
            intro: "Welcome to our App! We're excited to have you on board.",
            action: {
                instruction: "To verify your email please click on the following button",
                color: "#22BC66",
                text: "Verify your email",
                link: verificationUrl
            },
            outro: "Need help, or have a question? Just reply to this email, we'd love to help."
        }
    };
};

const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
    return {
        body: {
            name: username,
            intro: "We got a request to reset the password of your account ",
            action: {
                instruction: "To reset your password click on the following link",
                color: "#22bc4eff",
                text: "Reset password",
                link: passwordResetUrl,
            },
            outro: "Need help, or have a question? Just reply to this email, we'd love to help."
        }
    };
};

export {
     emailVerificationMailgenContent, 
     forgotPasswordMailgenContent,
     sendemail,
 };

