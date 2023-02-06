

https://github.com/taroserigano/Super_SimpleReact__Stripe_Practice

0. PAYMENT-INTENT

-is an API which accepts "amount" and then sends to stripe,
and then returns that paymentIntent to the front-end, which contains transaction info/id 

const stripe = new Stripe(process.env.SECRET_KEY);

export default async (req, res) => {
  if (req.method === "POST") {
    try {
      const { amount } = req.body;
      // Psst. For production-ready applications we recommend not using the
      // amount directly from the client without verifying it first. This is to
      // prevent bad actors from changing the total amount on the client before
      // it gets sent to the server. A good approach is to send the quantity of
      // a uniquely identifiable product and calculate the total price server-side.
      // Then, you would only fulfill orders using the quantity you charged for.

      const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency: "usd"
      });

res.status(200).send(paymentIntent,client_secret) 



1. LAYOUT: 

    
1. Load up stripe by loadStripe()  
<Elements stripe={stripePromise}>{children}</Elements>

    <Layout title="Donut Shop">
      <Row>
        <DonutShop
          onAddDonut={addDonut}
          onRemoveDonut={remDonut}
          numDonuts={numDonuts}
        />
      </Row>
      <CheckoutForm
        price={getDonutPrice(numDonuts)}
        onSuccessfulCheckout={() => Router.push("/success")}
      />
    </Layout>

*magic happens underneath the Layout 



2. CHECK OUT FORM: 

0. send *amount to payment_intent API, receive clientSecret(transaction info) 
1. get "payment_method" and "billing_details" 
2. send 'em to stripe, receive the return (which is paymentMethodReq) 
3. send to stripe again the clientSecret, "paymentMethodReq".ID 
4. if successful, redirect to "SUCCESS" page 



ELEMENT - that takes in pamentMethod 

    const cardElement = elements.getElement("card");
    
	// sends amount info to the payment_intents API 
    try {
      const { data: clientSecret } = await axios.post("/api/payment_intents", {
        amount: price * 100
      });

      const paymentMethodReq = await stripe.createPaymentMethod({
        type: "card",
        card: cardElement,
        billing_details: billingDetails
      });






















