package messaging

import "github.com/streadway/amqp"

// RabbitConfig defines all that is necessary to connect to a
type RabbitConfig struct {
	tlsDefinition
	URL string `json:"url"`
}

// ExchangeDefinition defines all the parameters for an exchange
type ExchangeDefinition struct {
	Name string `json:"name"`
	Type string `json:"type"`

	// defaulted usually
	Durable    bool       `json:"durable"`
	AutoDelete bool       `json:"auto_delete"`
	Internal   bool       `json:"internal"`
	NoWait     bool       `json:"no_wait"`
	Table      amqp.Table `json:"table"`
}

// QueueDefinition defines all the parameters for a queue
type QueueDefinition struct {
	Name       string `json:"name"`
	BindingKey string `json:"binding_key"`

	// defaulted usually
	Durable    bool       `json:"durable"`
	AutoDelete bool       `json:"auto_delete"`
	Exclusive  bool       `json:"exclusive"`
	NoWait     bool       `json:"no_wait"`
	Table      amqp.Table `json:"table"`
}

// DeliveryDefinition defines all the parameters for a delivery
type DeliveryDefinition struct {
	QueueName   string     `json:"queue_name"`
	ConsumerTag string     `json:"consumer_tag"`
	Exclusive   bool       `json:"exclusive"`
	NoACK       bool       `json:"no_ack"`
	NoLocal     bool       `json:"no_local"`
	NoWait      bool       `json:"no_wait"`
	Table       amqp.Table `json:"table"`
}

// NewExchangeDefinition builds an ExchangeDefinition with defaults
func NewExchangeDefinition(name, exType string) *ExchangeDefinition {
	return &ExchangeDefinition{
		Name:       name,
		Type:       exType,
		Durable:    true,
		AutoDelete: true,
		Internal:   false,
		NoWait:     false,
		Table:      nil,
	}
}

// NewQueueDefinition builds a QueueDefinition with defaults
func NewQueueDefinition(name, key string) *QueueDefinition {
	return &QueueDefinition{
		Name:       name,
		BindingKey: key,
		Durable:    true,
		AutoDelete: true,
		Exclusive:  false,
		NoWait:     false,
		Table:      nil,
	}
}

// NewDeliveryDefinition builds a DeliveryDefinition with defaults
func NewDeliveryDefinition(queueName string) *DeliveryDefinition {
	return &DeliveryDefinition{
		QueueName:   queueName,
		ConsumerTag: "cache-primer",
		NoACK:       false,
		NoLocal:     false,
		Exclusive:   false,
		NoWait:      false,
		Table:       nil,
	}
}

// ConnectToRabbit will open a TLS connection to rabbit mq
func ConnectToRabbit(config *RabbitConfig) (*amqp.Connection, error) {
	tlsConfig, err := config.TLSConfig()
	if err != nil {
		return nil, err
	}

	return amqp.DialTLS(config.URL, tlsConfig)
}

// BindWithDefaults will simplify the binding to use sane defaults
func BindWithDefaults(conn *amqp.Connection, exchangeName, exchangeType, queueName, bindKey string) (*amqp.Channel, *amqp.Queue, error) {
	exDef := NewExchangeDefinition(exchangeName, exchangeType)
	qDef := NewQueueDefinition(queueName, bindKey)

	return Bind(conn, exDef, qDef)
}

// Bind will connect to the exchange and queue defined
func Bind(conn *amqp.Connection, ex *ExchangeDefinition, queueDef *QueueDefinition) (*amqp.Channel, *amqp.Queue, error) {
	channel, err := conn.Channel()
	if err != nil {
		return nil, nil, err
	}

	err = channel.ExchangeDeclare(
		ex.Name,
		ex.Type,
		ex.Durable,
		ex.AutoDelete,
		ex.Internal,
		ex.NoWait,
		ex.Table,
	)
	if err != nil {
		return nil, nil, err
	}

	queue, err := channel.QueueDeclare(
		queueDef.Name,
		queueDef.Durable,
		queueDef.AutoDelete,
		queueDef.Exclusive,
		queueDef.NoWait,
		queueDef.Table,
	)
	if err != nil {
		return nil, nil, err
	}

	channel.QueueBind(
		queueDef.Name,
		queueDef.BindingKey,
		ex.Name,
		queueDef.NoWait,
		queueDef.Table,
	)
	if err != nil {
		return nil, nil, err
	}

	return channel, &queue, nil
}

// Consume start to consume off the queue specified
func Consume(channel *amqp.Channel, deliveryDef *DeliveryDefinition) (<-chan amqp.Delivery, error) {
	return channel.Consume(
		deliveryDef.QueueName,
		deliveryDef.ConsumerTag,
		deliveryDef.NoACK,
		deliveryDef.Exclusive,
		deliveryDef.NoLocal,
		deliveryDef.NoWait,
		deliveryDef.Table,
	)
}
