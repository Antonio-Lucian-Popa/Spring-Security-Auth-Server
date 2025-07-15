package com.asusoftware.SpringBootAuthServer.service;

public class ActivationEmailTemplate {

    public String buildActivationEmail(String name, String activationLink) {
        return """
        <div style="font-family: sans-serif; padding: 20px; color: #333;">
            <h2>Bine ai venit, %s!</h2>
            <p>Contul tău a fost creat cu succes. Pentru a-l activa, te rugăm să apeși pe butonul de mai jos:</p>
            <a href="%s" style="background: #4CAF50; padding: 10px 20px; color: white; text-decoration: none; border-radius: 5px;">
                Activează contul
            </a>
            <p>Dacă nu ai cerut crearea unui cont, ignoră acest email.</p>
            <br>
            <p>Cu drag,<br>Echipa Auth Server 🚀</p>
        </div>
        """.formatted(name, activationLink);
    }
    public String buildResetPasswordEmail(String name, String resetLink) {
        return """
        <div style="font-family: sans-serif; padding: 20px; color: #333;">
            <h2>Salut, %s!</h2>
            <p>Ai solicitat resetarea parolei. Pentru a continua, te rugăm să apeși pe butonul de mai jos:</p>
            <a href="%s" style="background: #4CAF50; padding: 10px 20px; color: white; text-decoration: none; border-radius: 5px;">
                Resetează parola
            </a>
            <p>Dacă nu ai solicitat acest lucru, ignoră acest email.</p>
            <br>
            <p>Cu drag,<br>Echipa Auth Server 🚀</p>
        </div>
        """.formatted(name, resetLink);
    }
}
